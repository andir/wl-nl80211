// SPDX-License-Identifier: MIT

use crate::{Nl80211Handle, Nl80211PhyGetRequest};

pub struct Nl80211PhyHandle(Nl80211Handle);

impl Nl80211PhyHandle {
    pub fn new(handle: Nl80211Handle) -> Self {
	Nl80211PhyHandle(handle)
    }

    /// Retrieve the wireless phys
    /// (equivalent to `iw phy`)
    pub fn get(&mut self) -> Nl80211PhyGetRequest {
	Nl80211PhyGetRequest::new(self.0.clone())
    }
}

