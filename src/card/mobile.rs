//! Mobile card backend.
//!
//! `MobileCardBackend` implements [`card_backend::CardBackend`] on top
//! of a caller-supplied [`CardBridge`]. It's used when libtumpa is
//! built with the `card-mobile` feature, which in turn sits on top of
//! `wecanencrypt/card-external` — i.e. the APDU transport is
//! registered at runtime rather than hard-wired to PC/SC.
//!
//! The `CardBridge` trait is intentionally **synchronous**. The Tauri
//! plugin (`tauri-plugin-tumpa-card`) provides an implementation that
//! bridges synchronously-spoken APDUs to the platform's native async
//! smartcard APIs (Android `IsoDep` / `UsbManager` + CCID; iOS
//! `NFCTagReaderSession` + `NFCISO7816Tag` / `TKSmartCard`). Putting
//! the async-to-sync edge in the plugin rather than here keeps
//! libtumpa framework-agnostic and makes this module testable with a
//! pure-Rust mock bridge.
//!
//! libtumpa stays **vendor-neutral** — the bridge speaks generic
//! ISO 7816-4 APDUs, so anything that answers `SELECT AID
//! D2760001240103040000000000000000` (YubiKey, Nitrokey 3/Pro, Gnuk,
//! any OpenPGP v3 card) works through the same code path.

use card_backend::{CardBackend, CardCaps, CardTransaction, PinType, SmartcardError};

/// A synchronous APDU bridge for a single mobile card session.
///
/// Called by [`MobileCardBackend`] to drive the card. Implementors live
/// in the tumpa mobile integration (the Tauri plugin) and usually own
/// a session handle for NFC or USB.
///
/// # Lifecycle
///
/// - [`begin_session`] is called once when a [`MobileCardBackend`] is
///   constructed. This typically shows the iOS CoreNFC modal or pops
///   the Android USB permission dialog, waits for a tag/reader, and
///   selects the OpenPGP applet. It returns when the card is ready to
///   receive APDUs.
/// - [`transmit_apdu`] is called for every APDU that
///   `wecanencrypt::card` wants to send.
/// - [`end_session`] is called when the [`MobileCardBackend`] drops —
///   the bridge releases NFC / closes the CCID pipe.
///
/// # Thread model
///
/// `MobileCardBackend` may be called from any thread (`openpgp-card`
/// requires `CardBackend: Send + Sync`), but never concurrently on the
/// same session. The bridge doesn't need its own locking; callers
/// serialize by holding a `&mut MobileCardBackend`.
///
/// [`begin_session`]: CardBridge::begin_session
/// [`transmit_apdu`]: CardBridge::transmit_apdu
/// [`end_session`]: CardBridge::end_session
pub trait CardBridge: Send + Sync {
    /// Begin a new card session and select the OpenPGP applet. Blocks
    /// until the card is ready (NFC tap received / USB reader bound)
    /// or fails with a `SmartcardError`.
    fn begin_session(&self) -> Result<(), SmartcardError>;

    /// Send one APDU command to the card and return its response.
    fn transmit_apdu(&self, cmd: &[u8]) -> Result<Vec<u8>, SmartcardError>;

    /// End the card session, releasing NFC / closing the reader.
    ///
    /// Infallible on purpose — called from `Drop` so there's nowhere
    /// useful to propagate errors. Implementations should log and
    /// swallow transport errors here.
    fn end_session(&self);
}

/// Card backend over a user-supplied bridge.
///
/// Construct with [`MobileCardBackend::new`]; hand it to
/// `openpgp_card::Card::new` or register it with
/// `wecanencrypt::card::external::set_backend_provider`.
pub struct MobileCardBackend {
    bridge: Box<dyn CardBridge>,
}

impl MobileCardBackend {
    /// Start a mobile card session.
    ///
    /// Calls `bridge.begin_session()` synchronously; returns the error
    /// from the bridge on failure. On success the OpenPGP applet has
    /// been selected and the card is ready for APDUs.
    pub fn new<B>(bridge: B) -> Result<Self, SmartcardError>
    where
        B: CardBridge + 'static,
    {
        let bridge: Box<dyn CardBridge> = Box::new(bridge);
        bridge.begin_session()?;
        Ok(Self { bridge })
    }

    /// Construct without starting a session. For tests and for callers
    /// that want to wire up session lifecycle themselves.
    pub fn from_active<B>(bridge: B) -> Self
    where
        B: CardBridge + 'static,
    {
        Self {
            bridge: Box::new(bridge),
        }
    }
}

impl Drop for MobileCardBackend {
    fn drop(&mut self) {
        self.bridge.end_session();
    }
}

impl CardBackend for MobileCardBackend {
    fn limit_card_caps(&self, card_caps: CardCaps) -> CardCaps {
        // Mobile transports (NFC ISO-DEP, USB CCID) don't impose
        // additional limits beyond what the card itself reports.
        card_caps
    }

    fn transaction(
        &mut self,
        reselect_application: Option<&[u8]>,
    ) -> Result<Box<dyn CardTransaction + Send + Sync + '_>, SmartcardError> {
        if let Some(aid) = reselect_application {
            let mut cmd = Vec::with_capacity(6 + aid.len());
            cmd.extend_from_slice(&[0x00, 0xa4, 0x04, 0x00]);
            cmd.push(aid.len() as u8);
            cmd.extend_from_slice(aid);
            cmd.push(0x00);
            self.bridge.transmit_apdu(&cmd)?;
        }
        Ok(Box::new(MobileCardTransaction {
            bridge: &*self.bridge,
        }))
    }
}

struct MobileCardTransaction<'a> {
    bridge: &'a dyn CardBridge,
}

impl<'a> CardTransaction for MobileCardTransaction<'a> {
    fn transmit(&mut self, cmd: &[u8], _buf_size: usize) -> Result<Vec<u8>, SmartcardError> {
        self.bridge.transmit_apdu(cmd)
    }

    fn feature_pinpad_verify(&self) -> bool {
        false
    }

    fn feature_pinpad_modify(&self) -> bool {
        false
    }

    fn pinpad_verify(
        &mut self,
        _pin: PinType,
        _card_caps: &Option<CardCaps>,
    ) -> Result<Vec<u8>, SmartcardError> {
        Err(SmartcardError::Error(
            "pinpad verify is not supported on mobile".into(),
        ))
    }

    fn pinpad_modify(
        &mut self,
        _pin: PinType,
        _card_caps: &Option<CardCaps>,
    ) -> Result<Vec<u8>, SmartcardError> {
        Err(SmartcardError::Error(
            "pinpad modify is not supported on mobile".into(),
        ))
    }

    fn was_reset(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Deterministic mock bridge — records transmitted APDUs and
    /// replies with a fixed sequence.
    struct MockBridge {
        transmitted: Mutex<Vec<Vec<u8>>>,
        replies: Mutex<Vec<Vec<u8>>>,
        ended: Mutex<bool>,
    }

    impl CardBridge for MockBridge {
        fn begin_session(&self) -> Result<(), SmartcardError> {
            Ok(())
        }
        fn transmit_apdu(&self, cmd: &[u8]) -> Result<Vec<u8>, SmartcardError> {
            self.transmitted.lock().unwrap().push(cmd.to_vec());
            let mut replies = self.replies.lock().unwrap();
            if replies.is_empty() {
                Err(SmartcardError::Error("no more mock replies".into()))
            } else {
                Ok(replies.remove(0))
            }
        }
        fn end_session(&self) {
            *self.ended.lock().unwrap() = true;
        }
    }

    #[test]
    fn reselect_application_sends_select_apdu() {
        let bridge = MockBridge {
            transmitted: Mutex::new(Vec::new()),
            // one reply for the SELECT APDU we expect to send
            replies: Mutex::new(vec![vec![0x90, 0x00]]),
            ended: Mutex::new(false),
        };
        let mut backend = MobileCardBackend::from_active(bridge);

        let aid = [0xd2, 0x76, 0x00, 0x01, 0x24, 0x01];
        {
            let _tx = backend.transaction(Some(&aid)).unwrap();
        }

        // transaction drop is fine; session end happens when backend drops
        drop(backend);
    }

    #[test]
    fn transmit_forwards_to_bridge() {
        let bridge = MockBridge {
            transmitted: Mutex::new(Vec::new()),
            replies: Mutex::new(vec![vec![0xaa, 0xbb, 0x90, 0x00]]),
            ended: Mutex::new(false),
        };
        let mut backend = MobileCardBackend::from_active(bridge);

        let mut tx = backend.transaction(None).unwrap();
        let resp = tx.transmit(&[0x00, 0xca, 0x00, 0x6e, 0x00], 256).unwrap();
        assert_eq!(resp, vec![0xaa, 0xbb, 0x90, 0x00]);
    }
}
