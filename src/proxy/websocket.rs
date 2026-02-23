use hyper::upgrade::Upgraded;
use tokio::io::copy_bidirectional;
use hyper_util::rt::TokioIo;
use anyhow::Result;

pub async fn tunnel(
    upgraded_client: Upgraded,
    upgraded_backend: Upgraded,
) -> Result<()> {

    let mut client_io = TokioIo::new(upgraded_client);
    let mut backend_io = TokioIo::new(upgraded_backend);

    let _ = copy_bidirectional(&mut client_io, &mut backend_io).await?;

    Ok(())
}
