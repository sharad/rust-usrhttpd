use hyper::upgrade::Upgraded;
use tokio::io::copy_bidirectional;
use anyhow::Result;

pub async fn tunnel(
    mut upgraded_client: Upgraded,
    mut upgraded_backend: Upgraded,
) -> Result<()> {
    let _ = copy_bidirectional(&mut upgraded_client, &mut upgraded_backend).await?;
    Ok(())
}

