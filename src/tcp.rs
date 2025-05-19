use bitflags::bitflags;
use etherparse::{IpNumber, TcpHeader};
use std::collections::{BTreeMap, VecDeque};
use std::{io, time};
use tun_tap::Iface;

bitflags! {
    pub(crate) struct Available: u8 {
        const READ = 0b00000001;
        const WRITE = 0b00000010;
    }
}

#[derive(Debug)]
pub enum State {
    Closed,
    // Listen,
    // SYN_SEND,
    SynRcvd,
    Estab,
    FinWait1,
    FinWait2,
    TimeWait,
    CloseWait,
    Closing,
    LastAck,
}

pub struct Connection {
    pub state: State,
    send: SendSequenceSpace,
    recv: RecvSequenceSpace,
    ip: etherparse::Ipv4Header,
    tcp: etherparse::TcpHeader,
    timers: Timers,

    pub(crate) incoming: VecDeque<u8>,
    pub(crate) unacked: VecDeque<u8>,

    pub(crate) closed: bool,
    closed_at: Option<u32>,
    max_incoming_buffer_size: usize, // the remian incoming buffer size
    send_window_update_ack: bool,
    time_wait_entry_time: Option<time::Instant>,
}

struct Timers {
    send_times: BTreeMap<u32, time::Instant>,
    srtt: f64,
}

impl Connection {
    pub(crate) fn is_rcv_closed(&self) -> bool {
        if let State::TimeWait = self.state {
            true
        } else {
            false
        }
    }

    fn availability(&self) -> Available {
        let mut a = Available::empty();
        if self.is_rcv_closed() || !self.incoming.is_empty() {
            a |= Available::READ;
        }
        a
    }

    fn calculate_advertised_window(&self) -> u16 {
        let occure_size = self.incoming.len();
        let avaliabe_size = self.max_incoming_buffer_size.saturating_sub(occure_size);

        std::cmp::min(avaliabe_size, u16::MAX as usize) as u16
    }
}

/// State of the Send Sequence Space (RFC 793 S3.2 F4)
///
/// ```
///            1         2          3          4
///       ----------|----------|----------|----------
///              SND.UNA    SND.NXT    SND.UNA
///                                   +SND.WND
///
/// 1 - old sequence numbers which have been acknowledged
/// 2 - sequence numbers of unacknowledged data
/// 3 - sequence numbers allowed for new data transmission
/// 4 - future sequence numbers which are not yet allowed
/// ```
///
#[allow(dead_code)]
struct SendSequenceSpace {
    /// send unacknowledged
    una: u32,
    /// send next
    nxt: u32,
    /// send window
    wnd: u16,
    /// send urgent pointer
    up: bool,
    /// segment sequence number used for last window update
    wl1: usize,
    /// segment acknowledgment number used for last window update
    wl2: usize,
    /// initial send sequence number
    iss: u32,
}

/// State of the Receive Sequence Space (RFC 793 S3.2 F5)
///
/// ```
///                1          2          3
///            ----------|----------|----------
///                   RCV.NXT    RCV.NXT
///                             +RCV.WND
///
/// 1 - old sequence numbers which have been acknowledged
/// 2 - sequence numbers allowed for new reception
/// 3 - future sequence numbers which are not yet allowed
/// ```
#[allow(dead_code)]
struct RecvSequenceSpace {
    /// receive next
    nxt: u32,
    /// receive window
    wnd: u16,
    /// receive urgent pointer
    up: bool,
    /// initial receive sequence number
    irs: u32,
}

#[allow(dead_code)]
#[allow(unused_variables)]
impl Connection {
    pub(crate) fn is_ready_for_removal(&self) -> bool {
        // A connection is ready for removal if its state is Closed.
        // This state is reached after RST, or after TIME_WAIT period expires.
        matches!(self.state, State::Closed)
    }
    pub fn accept<'a>(
        nic: &mut tun_tap::Iface,
        iph: etherparse::Ipv4HeaderSlice<'a>,
        tcph: etherparse::TcpHeaderSlice<'a>,
        data: &'a [u8],
    ) -> io::Result<Option<Self>> {
        if !tcph.syn() {
            // only expected SYN packet
            return Ok(None);
        }

        let iss = 0;
        let wnd = 1024;
        let mut c = Connection {
            timers: Timers {
                send_times: Default::default(),
                srtt: time::Duration::from_secs(1 * 60).as_secs_f64(),
            },
            state: State::SynRcvd,
            send: SendSequenceSpace {
                iss,
                una: iss,
                nxt: iss,
                wnd: wnd,
                up: false,

                wl1: 0,
                wl2: 0,
            },
            recv: RecvSequenceSpace {
                irs: tcph.sequence_number(),
                nxt: tcph.sequence_number() + 1,
                wnd: tcph.window_size(),
                up: false,
            },
            tcp: etherparse::TcpHeader::new(tcph.destination_port(), tcph.source_port(), iss, wnd),
            ip: etherparse::Ipv4Header::new(
                0,
                64,
                IpNumber::TCP,
                iph.destination_addr().octets(),
                iph.source_addr().octets(),
            )
            .unwrap(),

            incoming: Default::default(),
            unacked: Default::default(),

            closed: false,
            closed_at: None,
            max_incoming_buffer_size: 1024,
            send_window_update_ack: false,
            time_wait_entry_time: None,
        };

        // need to start establishing a connection
        c.tcp.syn = true;
        c.tcp.ack = true;
        c.send_window_update_ack = false;
        c.write(nic, c.send.nxt, 0)?;
        Ok(Some(c))
    }

    fn write(&mut self, nic: &mut tun_tap::Iface, seq: u32, mut limit: usize) -> io::Result<usize> {
        let mut buf = [0u8; 1500];
        self.tcp.sequence_number = seq;
        self.tcp.acknowledgment_number = self.recv.nxt;

        // println!(
        //     "write(ack: {}, seq: {}, limit: {}) syn {:?} fin {:?}",
        //     self.recv.nxt - self.recv.irs,
        //     seq,
        //     limit,
        //     self.tcp.syn,
        //     self.tcp.fin,
        // );

        let mut offset = seq.wrapping_sub(self.send.una) as usize;
        // we need to special-case the two "virtual" bytes SYN and FIN
        if let Some(closed_at) = self.closed_at {
            if seq == closed_at.wrapping_add(1) {
                // trying to write following FIN
                offset = 0;
                limit = 0;
            }
        }
        // println!(
        //     "using offset {} base {} in {:?}",
        //     offset,
        //     self.send.una,
        //     self.unacked.as_slices()
        // );
        let (mut h, mut t) = self.unacked.as_slices();
        if h.len() >= offset {
            h = &h[offset..];
        } else {
            let skipped = h.len();
            h = &[];
            t = &t[(offset - skipped)..];
        }

        let max_data = std::cmp::min(limit, h.len() + t.len());
        let size = std::cmp::min(
            buf.len(),
            self.tcp.header_len() as usize + self.ip.header_len() as usize + max_data,
        );
        self.ip
            .set_payload_len(size - self.ip.header_len() as usize)
            .unwrap();
        // calculate the remaining buffer size

        // write out the headers and the payload
        use std::io::Write;
        let buf_len = buf.len();
        let mut unwritten = &mut buf[..];

        self.ip.write(&mut unwritten)?;
        let ip_header_ends_at = buf_len - unwritten.len();

        // postpone writing the tcp header because we need the payload as one contiguous slice to calculate the tcp checksum
        unwritten = &mut unwritten[self.tcp.header_len() as usize..];
        let tcp_header_ends_at = buf_len - unwritten.len();

        // write out the payload
        let payload_bytes = {
            let mut written = 0;
            let mut limit = max_data;

            // first, write as much as we can from h
            let p1l = std::cmp::min(limit, h.len());
            written += unwritten.write(&h[..p1l])?;
            limit -= written;

            // then, write more (if we can) from t
            let p2l = std::cmp::min(limit, t.len());
            written += unwritten.write(&t[..p2l])?;
            written
        };
        let payload_ends_at = buf_len - unwritten.len();

        // finally we can calculate the tcp checksum and write out the tcp header
        self.tcp.checksum = self
            .tcp
            .calc_checksum_ipv4(&self.ip, &buf[tcp_header_ends_at..payload_ends_at])
            .expect("failed to compute checksum");

        let mut tcp_header_buf = &mut buf[ip_header_ends_at..tcp_header_ends_at];
        self.tcp.window_size = self.calculate_advertised_window();
        self.tcp.write(&mut tcp_header_buf)?;

        let mut next_seq = seq.wrapping_add(payload_bytes as u32);
        if self.tcp.syn {
            next_seq = next_seq.wrapping_add(1);
            self.tcp.syn = false;
        }
        if self.tcp.fin {
            next_seq = next_seq.wrapping_add(1);
            self.tcp.fin = false;
        }
        if wrapping_lt(self.send.nxt, next_seq) {
            self.send.nxt = next_seq;
        }
        self.timers.send_times.insert(seq, time::Instant::now());

        nic.send(&buf[..payload_ends_at])?;
        Ok(payload_bytes)
    }

    fn send_rst(&mut self, nic: &mut tun_tap::Iface) -> io::Result<()> {
        self.tcp.rst = true;
        self.tcp.sequence_number = 0;
        self.tcp.acknowledgment_number = 0;
        self.write(nic, self.send.nxt, 0)?;
        Ok(())
    }

    pub(crate) fn on_tick(&mut self, nic: &mut tun_tap::Iface) -> io::Result<()> {
        if let State::TimeWait = self.state {
            if let Some(entry_time) = self.time_wait_entry_time {
                const TIME_WAIT_DURATION: time::Duration = time::Duration::from_secs(30); // 2*MSL, typically 1-4 mins. Using 30s for quicker testing.
                if entry_time.elapsed() >= TIME_WAIT_DURATION {
                    eprintln!(
                        "[{}:{}] TIME_WAIT expired. Transitioning to Closed.",
                        std::net::Ipv4Addr::from(self.ip.destination),
                        self.tcp.destination_port
                    );
                    self.state = State::Closed; // Now it's truly closed
                    self.closed = true; // Redundant if State::Closed implies this, but good for clarity
                }
            }
            // In TIME_WAIT, we don't retransmit our data. We only ACK retransmitted FINs from the peer.
            // on_packet will handle sending ACKs if a FIN is received during TIME_WAIT.
            return Ok(());
        }

        if let State::Closed = self.state {
            // If already marked closed (e.g. by RST), do nothing.
            return Ok(());
        }
        if let State::FinWait2 | State::TimeWait = self.state {
            // we have shutdown our write side and the other side acked, no need to (re)transmit anything
            return Ok(());
        }

        // eprintln!("ON TICK: state {:?} una {} nxt {} unacked {:?}",
        //           self.state, self.send.una, self.send.nxt, self.unacked);

        let nunacked_data = self
            .closed_at
            .unwrap_or(self.send.nxt)
            .wrapping_sub(self.send.una);
        let nunsent_data = self.unacked.len() as u32 - nunacked_data;

        let waited_for = self
            .timers
            .send_times
            .range(self.send.una..)
            .next()
            .map(|t| t.1.elapsed());

        let should_retransmit = if let Some(waited_for) = waited_for {
            waited_for > time::Duration::from_secs(1)
                && waited_for.as_secs_f64() > 1.5 * self.timers.srtt
        } else {
            false
        };

        if should_retransmit {
            let resend = std::cmp::min(self.unacked.len() as u32, self.send.wnd as u32);
            if resend < self.send.wnd as u32 && self.closed {
                // can we include the FIN?
                self.tcp.fin = true;
                self.closed_at = Some(self.send.una.wrapping_add(self.unacked.len() as u32));
            }
            self.write(nic, self.send.una, resend as usize)?;
        } else {
            // we should send new data if we have new data and space in the window
            if nunsent_data == 0 && self.closed_at.is_some() {
                return Ok(());
            }

            let allowed = self.send.wnd as u32 - nunacked_data;
            if allowed == 0 {
                return Ok(());
            }

            let send = std::cmp::min(nunsent_data, allowed);
            if send < allowed && self.closed && self.closed_at.is_none() {
                self.tcp.fin = true;
                self.closed_at = Some(self.send.una.wrapping_add(self.unacked.len() as u32));
            }

            self.write(nic, self.send.nxt, send as usize)?;
        }

        Ok(())
    }

    // todo need to add the ip parser
    pub(crate) fn on_packet<'a>(
        &mut self,
        nic: &mut tun_tap::Iface,
        iph: etherparse::Ipv4HeaderSlice<'a>,
        tcph: etherparse::TcpHeaderSlice<'a>,
        data: &'a [u8],
    ) -> io::Result<Available> {
        // first, check that sequence numbers are valid (RFC 793 S3.3)
        let seqn = tcph.sequence_number();
        let mut slen = data.len() as u32;
        if tcph.fin() {
            slen += 1;
        };
        if tcph.syn() {
            slen += 1;
        };
        let wend = self.recv.nxt.wrapping_add(self.recv.wnd as u32);
        let okay = if slen == 0 {
            // zero-length segment has separate rules for acceptance
            if self.recv.wnd == 0 {
                if seqn != self.recv.nxt { false } else { true }
            } else if !is_between_wrapped(self.recv.nxt.wrapping_sub(1), seqn, wend) {
                false
            } else {
                true
            }
        } else {
            if self.recv.wnd == 0 {
                false
            } else if !is_between_wrapped(self.recv.nxt.wrapping_sub(1), seqn, wend)
                && !is_between_wrapped(
                    self.recv.nxt.wrapping_sub(1),
                    seqn.wrapping_add(slen - 1),
                    wend,
                )
            {
                false
            } else {
                true
            }
        };

        if !okay {
            eprintln!("NOT OKAY");
            self.write(nic, self.send.nxt, 0)?;
            return Ok(self.availability());
        }

        if !tcph.ack() {
            if tcph.syn() {
                // got SYN part of initial handshake
                assert!(data.is_empty());
                self.recv.nxt = seqn.wrapping_add(1);
            }
            return Ok(self.availability());
        }

        let ackn = tcph.acknowledgment_number();
        if let State::SynRcvd = self.state {
            if is_between_wrapped(
                self.send.una.wrapping_sub(1),
                ackn,
                self.send.nxt.wrapping_add(1),
            ) {
                // must have ACKed our SYN, since we detected at least one acked byte,
                // and we have only sent one byte (the SYN).
                self.state = State::Estab;
            } else {
            }
        }

        if let State::Estab | State::FinWait1 | State::FinWait2 = self.state {
            if is_between_wrapped(self.send.una, ackn, self.send.nxt.wrapping_add(1)) {
                println!(
                    "ack for {} (last: {}); prune in {:?}",
                    ackn, self.send.una, self.unacked
                );
                if !self.unacked.is_empty() {
                    let data_start = if self.send.una == self.send.iss {
                        // send.una hasn't been updated yet with ACK for our SYN, so data starts just beyond it
                        self.send.una.wrapping_add(1)
                    } else {
                        self.send.una
                    };
                    let acked_data_end =
                        std::cmp::min(ackn.wrapping_sub(data_start) as usize, self.unacked.len());
                    self.unacked.drain(..acked_data_end);

                    let old = std::mem::replace(&mut self.timers.send_times, BTreeMap::new());

                    let una = self.send.una;
                    let srtt = &mut self.timers.srtt;
                    self.timers
                        .send_times
                        .extend(old.into_iter().filter_map(|(seq, sent)| {
                            if is_between_wrapped(una, seq, ackn) {
                                *srtt = 0.8 * *srtt + (1.0 - 0.8) * sent.elapsed().as_secs_f64();
                                None
                            } else {
                                Some((seq, sent))
                            }
                        }));
                }
                self.send.una = ackn;
            }
        }

        if let State::FinWait1 = self.state {
            if let Some(closed_at) = self.closed_at {
                if self.send.una == closed_at.wrapping_add(1) {
                    // our FIN has been ACKed!
                    self.state = State::FinWait2;
                }
            }
        }

        if !data.is_empty() {
            if let State::Estab | State::FinWait1 | State::FinWait2 = self.state {
                let mut unread_data_at = self.recv.nxt.wrapping_sub(seqn) as usize;
                if unread_data_at > data.len() {
                    // we must have received a re-transmitted FIN that we have already seen
                    // nxt points to beyond the fin, but the fin is not in data!
                    assert_eq!(unread_data_at, data.len() + 1);
                    unread_data_at = 0;
                }
                self.incoming.extend(&data[unread_data_at..]);

                /*
                Once the TCP takes responsibility for the data it advances
                RCV.NXT over the data accepted, and adjusts RCV.WND as
                apporopriate to the current buffer availability.  The total of
                RCV.NXT and RCV.WND should not be reduced.
                 */
                self.recv.nxt = seqn.wrapping_add(data.len() as u32);

                // Send an acknowledgment of the form: <SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>
                self.write(nic, self.send.nxt, 0)?;
            }
        }
        if tcph.fin() {
            eprintln!(
                // Access IP and port using the correct field names
                "[{}:{}] Received FIN. Current state: {:?}, FIN seq: {}, Our recv.nxt: {}",
                std::net::Ipv4Addr::from(self.ip.destination), // Remote IP (destination IP of packets we receive)
                self.tcp.destination_port, // Remote port (destination port of packets we receive)
                self.state,
                tcph.sequence_number(),
                self.recv.nxt
            );

            match self.state {
                State::SynRcvd => {
                    eprintln!(
                        "[{}:{}] FIN received in SynRcvd state.",
                        std::net::Ipv4Addr::from(self.ip.destination),
                        self.tcp.destination_port
                    );
                    if tcph.sequence_number() == self.recv.nxt {
                        self.recv.nxt = self.recv.nxt.wrapping_add(1);
                    } else {
                        eprintln!(
                            "[{}:{}] SynRcvd: FIN with unexpected sequence. Expected {}, got {}. Sending ACK for expected.",
                            std::net::Ipv4Addr::from(self.ip.destination),
                            self.tcp.destination_port,
                            self.recv.nxt,
                            tcph.sequence_number()
                        );
                    }
                    if let Err(e) = self.write(nic, self.send.nxt, 0) {
                        eprintln!(
                            "[{}:{}] SynRcvd: Error sending ACK for FIN: {}",
                            std::net::Ipv4Addr::from(self.ip.destination),
                            self.tcp.destination_port,
                            e
                        );
                        return Err(e);
                    }
                    self.state = State::CloseWait;
                    eprintln!(
                        "[{}:{}] SynRcvd: Sent ACK for FIN. Transitioned to {:?}.",
                        std::net::Ipv4Addr::from(self.ip.destination),
                        self.tcp.destination_port,
                        self.state
                    );
                }
                State::Estab => {
                    eprintln!(
                        "[{}:{}] FIN received in Estab state.",
                        std::net::Ipv4Addr::from(self.ip.destination),
                        self.tcp.destination_port
                    );
                    if tcph.sequence_number() == self.recv.nxt {
                        self.recv.nxt = self.recv.nxt.wrapping_add(1);
                    } else {
                        eprintln!(
                            "[{}:{}] Estab: FIN with unexpected sequence. Expected {}, got {}. Sending ACK for expected.",
                            std::net::Ipv4Addr::from(self.ip.destination),
                            self.tcp.destination_port,
                            self.recv.nxt,
                            tcph.sequence_number()
                        );
                    }
                    if let Err(e) = self.write(nic, self.send.nxt, 0) {
                        eprintln!(
                            "[{}:{}] Estab: Error sending ACK for FIN: {}",
                            std::net::Ipv4Addr::from(self.ip.destination),
                            self.tcp.destination_port,
                            e
                        );
                        return Err(e);
                    }
                    self.state = State::CloseWait;
                    eprintln!(
                        "[{}:{}] Estab: Transitioned to CloseWait state.",
                        std::net::Ipv4Addr::from(self.ip.destination),
                        self.tcp.destination_port
                    );
                }
                State::FinWait1 => {
                    eprintln!(
                        "[{}:{}] FIN received in FinWait1 state.",
                        std::net::Ipv4Addr::from(self.ip.destination),
                        self.tcp.destination_port
                    );
                    if tcph.sequence_number() == self.recv.nxt {
                        self.recv.nxt = self.recv.nxt.wrapping_add(1);
                    } else {
                        eprintln!(
                            "[{}:{}] FinWait1: FIN with unexpected sequence. Expected {}, got {}. Sending ACK for expected.",
                            std::net::Ipv4Addr::from(self.ip.destination),
                            self.tcp.destination_port,
                            self.recv.nxt,
                            tcph.sequence_number()
                        );
                    }
                    if let Err(e) = self.write(nic, self.send.nxt, 0) {
                        eprintln!(
                            "[{}:{}] FinWait1: Error sending ACK for peer's FIN: {}",
                            std::net::Ipv4Addr::from(self.ip.destination),
                            self.tcp.destination_port,
                            e
                        );
                        return Err(e);
                    }
                    eprintln!(
                        "[{}:{}] FinWait1: Sent ACK for peer's FIN.",
                        std::net::Ipv4Addr::from(self.ip.destination),
                        self.tcp.destination_port
                    );

                    if let Some(our_fin_seq_plus_one) = self.closed_at.map(|s| s.wrapping_add(1)) {
                        if self.send.una >= our_fin_seq_plus_one {
                            self.state = State::TimeWait;
                            eprintln!(
                                "[{}:{}] FinWait1: Transitioned to TimeWait (our FIN was ACKed).",
                                std::net::Ipv4Addr::from(self.ip.destination),
                                self.tcp.destination_port
                            );
                        } else {
                            self.state = State::Closing;
                            eprintln!(
                                "[{}:{}] FinWait1: Transitioned to Closing (our FIN not yet ACKed).",
                                std::net::Ipv4Addr::from(self.ip.destination),
                                self.tcp.destination_port
                            );
                        }
                    } else {
                        eprintln!(
                            "[{}:{}] Warning: FinWait1 but self.closed_at is None. Assuming our FIN not ACKed.",
                            std::net::Ipv4Addr::from(self.ip.destination),
                            self.tcp.destination_port
                        );
                        self.state = State::Closing;
                    }
                }
                State::FinWait2 => {
                    eprintln!(
                        "[{}:{}] FIN received in FinWait2 state.",
                        std::net::Ipv4Addr::from(self.ip.destination),
                        self.tcp.destination_port
                    );
                    if tcph.sequence_number() == self.recv.nxt {
                        self.recv.nxt = self.recv.nxt.wrapping_add(1);
                    } else {
                        eprintln!(
                            "[{}:{}] FinWait2: FIN with unexpected sequence. Expected {}, got {}. Sending ACK for expected.",
                            std::net::Ipv4Addr::from(self.ip.destination),
                            self.tcp.destination_port,
                            self.recv.nxt,
                            tcph.sequence_number()
                        );
                    }
                    if let Err(e) = self.write(nic, self.send.nxt, 0) {
                        eprintln!(
                            "[{}:{}] FinWait2: Error sending ACK for peer's FIN: {}",
                            std::net::Ipv4Addr::from(self.ip.destination),
                            self.tcp.destination_port,
                            e
                        );
                        return Err(e);
                    }
                    self.state = State::TimeWait;
                    eprintln!(
                        "[{}:{}] FinWait2: Transitioned to TimeWait state.",
                        std::net::Ipv4Addr::from(self.ip.destination),
                        self.tcp.destination_port
                    );
                }
                State::CloseWait => {
                    eprintln!(
                        "[{}:{}] FIN (likely retransmission) received in CloseWait. Resending ACK.",
                        std::net::Ipv4Addr::from(self.ip.destination),
                        self.tcp.destination_port
                    );
                    if let Err(e) = self.write(nic, self.send.nxt, 0) {
                        eprintln!(
                            "[{}:{}] CloseWait: Error resending ACK for FIN: {}",
                            std::net::Ipv4Addr::from(self.ip.destination),
                            self.tcp.destination_port,
                            e
                        );
                    }
                }
                State::Closing => {
                    eprintln!(
                        "[{}:{}] FIN (likely retransmission) received in Closing. Resending ACK.",
                        std::net::Ipv4Addr::from(self.ip.destination),
                        self.tcp.destination_port
                    );
                    if let Err(e) = self.write(nic, self.send.nxt, 0) {
                        eprintln!(
                            "[{}:{}] Closing: Error resending ACK for FIN: {}",
                            std::net::Ipv4Addr::from(self.ip.destination),
                            self.tcp.destination_port,
                            e
                        );
                    }
                }
                State::LastAck => {
                    eprintln!(
                        "[{}:{}] FIN (likely retransmission) received in LastAck. Resending ACK.",
                        std::net::Ipv4Addr::from(self.ip.destination),
                        self.tcp.destination_port
                    );
                    if let Err(e) = self.write(nic, self.send.nxt, 0) {
                        eprintln!(
                            "[{}:{}] LastAck: Error resending ACK: {}",
                            std::net::Ipv4Addr::from(self.ip.destination),
                            self.tcp.destination_port,
                            e
                        );
                    }
                }
                State::TimeWait => {
                    eprintln!(
                        "[{}:{}] FIN (likely retransmission) received in TimeWait. Resending final ACK.",
                        std::net::Ipv4Addr::from(self.ip.destination),
                        self.tcp.destination_port
                    );
                    if let Err(e) = self.write(nic, self.send.nxt, 0) {
                        eprintln!(
                            "[{}:{}] TimeWait: Error resending ACK for FIN: {}",
                            std::net::Ipv4Addr::from(self.ip.destination),
                            self.tcp.destination_port,
                            e
                        );
                    }
                }
                State::Closed => {
                    eprintln!(
                        "[{}:{}] FIN received in Closed state. Ignoring.",
                        std::net::Ipv4Addr::from(self.ip.destination),
                        self.tcp.destination_port
                    );
                } // State::SynRcvd
                  // This branch is already handled above. This would be required by Rust for exhaustive matching.
                  // Previously, the `(s_)` pattern captured any unspecified states, including SynRcvd.
                  // If all states are explicitly listed, then we don't need a `_` or `(s_)` pattern.
            }
        }
        if tcph.rst() {
            eprintln!(
                "[{}:{}] Received RST. Aborting connection. State was: {:?}",
                std::net::Ipv4Addr::from(self.ip.destination),
                self.tcp.destination_port,
                self.state
            );
            // Mark the connection as needing immediate closure and removal
            self.state = State::Closed; // You need a Closed state or special flag
            self.closed = true; // Ensure application-layer read/write will fail
            // Notify application layer that connection was aborted
            // Return a special Available status or error to let packet_loop know it can remove this
            // For example: return Err(io::Error::new(io::ErrorKind::ConnectionReset, "Connection reset by peer"));
            // Or through Available flags
            // available.set(tcp::Available::CLOSED_BY_RST, true);
            return Ok(self.availability()); // Or a special value indicating need for removal
        }

        Ok(self.availability())
    }

    pub(crate) fn close(&mut self, nic: &mut Iface, tcph: &TcpHeader) -> io::Result<()> {
        io::Result::Ok(())
    }
    pub(crate) fn initiate_active_close(&mut self) {
        eprintln!(
            "[{}:{}] Application requesting to close connection (active close). Current state: {:?}",
            std::net::Ipv4Addr::from(self.ip.destination),
            self.tcp.destination_port,
            self.state
        );

        match self.state {
            State::Estab => {
                self.state = State::FinWait1;
                self.closed = true; // Mark our end as closed for sending
                // The FIN will be sent by on_tick or next data write
            }
            State::CloseWait => {
                // Received FIN from peer, now app closes
                self.state = State::LastAck;
                self.closed = true; // Mark our end as closed for sending
                // The FIN will be sent by on_tick or next data write
            }
            State::SynRcvd => {
                // App closes before connection fully established
                // This is a bit tricky. Sending FIN is one option. Sending RST might be more appropriate for abort.
                // For simplicity, let's try to send a FIN.
                self.state = State::FinWait1; // Or directly to Closed and send RST
                self.closed = true;
            }
            // If already in a closing state (FinWait1, FinWait2, Closing, LastAck, TimeWait) or Closed, do nothing.
            _ => {
                eprintln!(
                    "[{}:{}] Shutdown called on connection in state {:?}, no action.",
                    std::net::Ipv4Addr::from(self.ip.destination),
                    self.tcp.destination_port,
                    self.state
                );
            }
        }
    }

    /// Call this when a connection enters TIME_WAIT state.
    pub(crate) fn enter_time_wait(&mut self) {
        eprintln!(
            "[{}:{}] Connection entering TIME_WAIT.",
            std::net::Ipv4Addr::from(self.ip.destination),
            self.tcp.destination_port
        );
        self.state = State::TimeWait;
        self.time_wait_entry_time = Some(time::Instant::now());
    }

    /// Call this when an RST is received or a fatal error occurs.
    pub(crate) fn enter_closed_due_to_rst_or_error(&mut self, reason: &str) {
        eprintln!(
            "[{}:{}] Connection moving to Closed. Reason: {}. Current state: {:?}",
            std::net::Ipv4Addr::from(self.ip.destination),
            self.tcp.destination_port,
            reason,
            self.state
        );
        self.state = State::Closed;
        self.closed = true; // Ensure application layer sees it as closed too
        // Any other cleanup specific to the Connection struct if needed
    }
}

fn wrapping_lt(lhs: u32, rhs: u32) -> bool {
    lhs.wrapping_sub(rhs) > (1 << 31)
}

fn is_between_wrapped(start: u32, x: u32, end: u32) -> bool {
    wrapping_lt(start, x) && wrapping_lt(x, end)
}
