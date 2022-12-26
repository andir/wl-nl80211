// SPDX-License-Identifier: MIT

use futures::TryStream;
use netlink_packet_generic::GenlMessage;

use crate::{nl80211_execute, Nl80211Error, Nl80211Handle, Nl80211Message};

pub struct Nl80211PhyGetRequest {
    handle: Nl80211Handle,
}

impl Nl80211PhyGetRequest {
    pub(crate) fn new(handle: Nl80211Handle) -> Self {
        Nl80211PhyGetRequest { handle }
    }

    pub async fn execute(
        self,
    ) -> impl TryStream<Ok = GenlMessage<Nl80211Message>, Error = Nl80211Error>
    {
	let Nl80211PhyGetRequest { mut handle } = self;

	let nl80211_msg = Nl80211Message::new_phy_get();
	nl80211_execute(&mut handle, nl80211_msg).await
    }
}
