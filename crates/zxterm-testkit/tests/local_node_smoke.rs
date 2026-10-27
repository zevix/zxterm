//! Acceptance smoke test: starts and stops a `LocalNode` when `freenet` is
//! on `PATH`, and skips with a printed reason when it is not.

use zxterm_testkit::local_node::{LocalNode, OWNER_PORT, freenet_available};

#[test]
fn starts_and_stops_a_local_node() {
    if !freenet_available() {
        println!("SKIP starts_and_stops_a_local_node: freenet binary not on PATH");
        return;
    }

    let mut node = LocalNode::start().expect("start a local freenet node");
    assert_ne!(node.port, OWNER_PORT);
    assert!(node.pid > 0);
    assert!(node.dir().is_dir());

    node.stop().expect("stop the local freenet node");
    assert!(
        !node.dir().exists(),
        "scratch directory must be removed after stop()"
    );
}
