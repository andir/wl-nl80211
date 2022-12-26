// SPDX-License-Identifier: MIT

use futures::stream::TryStreamExt;

#[tokio::main]
async fn main() {
    let (connection, handle, _) = wl_nl80211::new_connection().unwrap();
    tokio::spawn(connection);

    get_interfaces(handle.clone()).await;
    get_phys(handle.clone()).await;
}

async fn get_interfaces(handle: wl_nl80211::Nl80211Handle) {
    let mut interface_handle = handle.interface().get().execute().await;

    let mut msgs = Vec::new();
    while let Some(msg) = interface_handle.try_next().await.unwrap() {
        msgs.push(msg);
    }
    assert!(!msgs.is_empty());
    for msg in msgs {
        println!("{:?}", msg);
    }
}

async fn get_phys(handle: wl_nl80211::Nl80211Handle) {
    let mut phy_handle = handle.phy().get().execute().await;

    let mut msgs = Vec::new();
    while let Some(msg) = phy_handle.try_next().await.unwrap() {
        msgs.push(msg);
    }
    assert!(!msgs.is_empty());
    for msg in msgs {
        println!("{:?}", msg);
    }
}

