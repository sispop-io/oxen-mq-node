
const sispopmq = require('./build/Release/sispopmq.node');

// console.log('sispopmq', sispopmq);

let a = new sispopmq.Address(
        'tcp+curve://129.151.164.202:22843/4e63f016b964bb8620e6763974c34505d27a95aad8f9465a55287cabbfc9cd7d');


async function init() {
    console.log('starting');
    let omq = new sispopmq.SispopMQ();
    omq.start()

    console.log('connecting to', a.fullAddress);
    // Non-async (we get the id right away, and will queue the request to be sent once fully
    // requested):
    let c = omq.connectRemote(a);

    // Or we could do an await for the connection to be fully established before we proceed:
    /*
    try {
        c = await omq.connectRemoteAsync(a);
    } catch (error) {
        console.log('connection failed: ', error);
        return;
    }
    */

    let r;
    try {
        r = await omq.request(c, 'rpc.get_info', [], {"timeout": 3000});
    } catch (err) {
        console.log('fail: got back', err.length, 'parts');
        return;
    }

    console.log('success: got back', r.length, 'parts');
    console.log(r[0].toString('utf8'));
    console.log(r[1].toString('utf8'));

    omq.disconnect(c);

    console.log('done');
}
init()
