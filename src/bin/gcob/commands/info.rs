use anyhow::Result;
use tonic::transport::Channel;

use super::{insert_header, sanitize};

pub async fn run(channel: Channel, rune: &str, client_id: &str) -> Result<()> {
    let mut client = gcob::cln::cln_api::node_services_client::NodeServicesClient::new(channel);

    let mut request = tonic::Request::new(gcob::cln::cln_api::GetinfoRequest {});
    insert_header(request.metadata_mut(), "x-rune", rune)?;
    insert_header(request.metadata_mut(), "x-client-id", client_id)?;

    let response = client.getinfo(request).await?.into_inner();

    let id_hex = hex::encode(&response.id);
    let color_hex = hex::encode(&response.color);

    println!("Node Information:");
    println!("  Alias: {}", sanitize(&response.alias));
    println!("  ID: {}", id_hex);
    println!("  Color: #{}", color_hex);
    println!("  Peers: {}", response.num_peers);
    println!("  Channels: {}", response.num_active_channels);
    println!("  Block height: {}", response.blockheight);
    println!("  Network: {}", sanitize(&response.network));
    println!("  Version: {}", sanitize(&response.version));
    println!("  Lightning dir: {}", sanitize(&response.lightning_dir));

    Ok(())
}
