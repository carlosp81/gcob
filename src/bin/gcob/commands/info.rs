use anyhow::{Context, Result};
use tonic::transport::Channel;

pub async fn run(channel: Channel) -> Result<()> {
    let rune = std::env::var("GCOD_RUNE").context("GCOD_RUNE not set")?;

    let mut client = gcob::cln::cln_api::node_services_client::NodeServicesClient::new(channel);

    let mut request = tonic::Request::new(gcob::cln::cln_api::GetinfoRequest {});
    request
        .metadata_mut()
        .insert("x-rune", rune.parse().unwrap());

    let response = client.getinfo(request).await?.into_inner();

    let id_hex = hex::encode(&response.id);
    let color_hex = hex::encode(&response.color);

    println!("Node Information:");
    println!("  Alias: {}", response.alias);
    println!("  ID: {}", id_hex);
    println!("  Color: #{}", color_hex);
    println!("  Peers: {}", response.num_peers);
    println!("  Channels: {}", response.num_active_channels);
    println!("  Block height: {}", response.blockheight);
    println!("  Network: {}", response.network);
    println!("  Version: {}", response.version);
    println!("  Lightning dir: {}", response.lightning_dir);

    Ok(())
}
