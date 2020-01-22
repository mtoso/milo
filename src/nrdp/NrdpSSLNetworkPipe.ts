import { NetworkPipe, OnData, OnClose, OnError, DnsResult, CreateSSLNetworkPipeOptions } from "../types";
import { NrdpPlatform } from "./NrdpPlatform";
import N from "./ScriptSocket";
import nrdp from "./nrdp";
import { assert } from "../utils";
import { default as BasePlatform } from "../Platform";

const Platform = <NrdpPlatform>(BasePlatform);

function set_mem_eof_return(platform: NrdpPlatform, bio: N.Struct) {
    platform.BIO_ctrl(bio, platform.BIO_C_SET_BUF_MEM_EOF_RETURN, -1, undefined);
}

class NrdpSSLNetworkPipe implements NetworkPipe
{
    private ssl: N.Struct;
    private ssl_ctx: N.Struct;
    // private bio: N.BIO;
    private inputBio: N.Struct;
    private outputBio: N.Struct;
    private pipe: NetworkPipe;
    private connected: boolean;
    private writeBuffers: (Uint8Array|ArrayBuffer|string)[];
    private writeBufferOffsets: number[];
    private writeBufferLengths: number[];
    private connectedCallback?: (error?: Error) => void;

    constructor(options: CreateSSLNetworkPipeOptions, callback: (error?: Error) => void)
    {
        this.connectedCallback = callback;
        this.connected = false;
        this.writeBuffers = [];
        this.writeBufferOffsets = [];
        this.writeBufferLengths = [];

        this.pipe = options.pipe;
        const meth = Platform.TLS_client_method();
        this.ssl_ctx = Platform.SSL_CTX_new(meth);
        this.ssl_ctx.free = "SSL_CTX_free";
        let ret = Platform.SSL_CTX_ctrl(this.ssl_ctx, Platform.SSL_CTRL_MODE, Platform.SSL_MODE_RELEASE_BUFFERS, undefined);
        Platform.log("BALLS", ret);
        /* SSL_SET_OPTION(0); */
        let ctx_options = Platform.SSL_OP_NO_SSLv3;
        ret = Platform.SSL_CTX_set_options(this.ssl_ctx, ctx_options);
        Platform.log("BALLS 2", ret);

        const cert_store = Platform.SSL_CTX_get_cert_store(this.ssl_ctx);
        const shit = Platform.trustStore();
        Platform.log("BALLS3", typeof shit);
        Platform.trustStore().forEach((x509: N.Struct) => {
            Platform.X509_STORE_add_cert(cert_store, x509);
        });
        const param = Platform.X509_VERIFY_PARAM_new();
        Platform.X509_VERIFY_PARAM_set_time(param, Math.round(nrdp.now() / 1000));
        Platform.SSL_CTX_set1_param(this.ssl_ctx, param);
        Platform.X509_VERIFY_PARAM_free(param);

        this.ssl = Platform.SSL_new(this.ssl_ctx);
        Platform.SSL_set_default_read_buffer_len(this.ssl, 16384);
        Platform.SSL_up_ref(this.ssl);
        Platform.SSL_set_read_ahead(this.ssl, 1);
        // if (0) {
            // this.inputBio = Platform.BIO_new_socket(sock, Platform.BIO_NOCLOSE);
            // this.inputBio.free = "BIO_free";
            // // Platform.BIO_set_read_buffer_size(this.bio, 16384);
            // 	Platform.log("ball", Platform.BIO_int_ctrl(this.bio, Platform.BIO_C_SET_BUFF_SIZE, 16384, 0));

        const memMethod = Platform.BIO_s_mem();
        this.inputBio = Platform.BIO_new(memMethod);
        set_mem_eof_return(Platform, this.inputBio);

        this.inputBio.free = "BIO_free";

        this.outputBio = Platform.BIO_new(memMethod);
        set_mem_eof_return(Platform, this.outputBio);
        this.outputBio.free = "BIO_free";
        this.pipe.ondata = () => {
            Platform.log("FAEN");
            const read = this.pipe.read(Platform.scratch, 0, Platform.scratch.byteLength);
            if (!read) {
                assert(this.pipe.closed, "Should be closed already");
                return;
            }
            Platform.log("got data", read);
            assert(read > 0, "This should be > 0");
            // throw new Error("fiskball");
            const written = Platform.BIO_write(this.inputBio, Platform.scratch, 0, read);
            nrdp.l("wrote", read, "bytes to inputBio =>", written);
            if (!this.connected) {
                this._connect();
            } else {
                this._readFromBIO();
            }
        };
        this.pipe.onclose = () => {
            Platform.log("got close", Platform.stacktrace());
        };
        this.pipe.onerror = (code: number, message?: string) => {
            Platform.log("got error", code, message || "");
        };

        Platform.SSL_set_bio(this.ssl, this.inputBio, this.outputBio);
        this._connect();
    }

    get closed() { return this.pipe.closed; }

    write(buf: Uint8Array | ArrayBuffer | string, offset?: number, length?: number): void
    {
        if (typeof buf === 'string') {
            length = buf.length;
        } else if (length === undefined) {
            length = buf.byteLength;
        }
        offset = offset || 0;

        if (!length)
            throw new Error("0 length write");

        Platform.log("write called 2", buf, offset, length);

        if (!this.connected) {
            Platform.log("driti?");

            throw new Error("SSLNetworkPipe is not connected");
        }

        Platform.log("drit?");
        let written;
        try {
            written = this.writeBuffers.length ? -1 : Platform.BIO_write(this.inputBio, buf, offset, length);
            Platform.log("drit!");
            Platform.log("wrote to output bio", length, "=>", written);
        } catch (err) {
            Platform.log("got err", err);
        }

        if (written === -1) {
            this.writeBuffers.push(buf);
            this.writeBufferOffsets.push(offset || 0);
            this.writeBufferLengths.push(length);
        }
    }

    read(buf: Uint8Array | ArrayBuffer, offset: number, length: number): number
    {
        return -1;
    }

    close(): void
    {

    }

    private _readFromBIO()
    {

    }

    private _connect()
    {
        assert(this.connectedCallback);
        let ret = Platform.SSL_connect(this.ssl);
        Platform.log("CALLED CONNECT", ret);
        if (ret <= 0) {
            Platform.log("GOT ERROR FROM SSL_CONNECT", Platform.SSL_get_error(this.ssl, ret),
                              Platform.ERR_error_string(Platform.SSL_get_error(this.ssl, ret)));
            if (Platform.SSL_get_error(this.ssl, ret) == Platform.SSL_ERROR_WANT_READ) {
                const pending = Platform.BIO_ctrl_pending(this.outputBio);
                // assert(pending <= this.scratch.byteLength, "Pending too large. Probably have to increase scratch buffer size");
                if (pending > 0) {
                    const buf = new ArrayBuffer(pending);
                    let read = Platform.BIO_read(this.outputBio, buf, pending);
                    assert(read === pending, "Read should be pending");
                    this.pipe.write(buf, 0, read);
                    // Platform
                }
                Platform.log("got pending", pending);
                // N.setFD(sock, N.READ, onConnected.bind(this, host));
            } else {
                Platform.log("BIG FAILURE", Platform.SSL_get_error(this.ssl, ret), N.errno);
                this.connectedCallback(new Error(`SSL_connect failure ${Platform.SSL_get_error(this.ssl, ret)} ${N.errno}`));
                this.connectedCallback = undefined;
            }
        } else {
            Platform.log("sheeeet", ret);
            assert(ret === 1, "This should be 1");
            Platform.log("we're connected");
            this.connected = true;
            assert(this.connectedCallback);
            this.connectedCallback();
            this.connectedCallback = undefined;
        }
    }

    ondata?: OnData;
    onclose?: OnClose;
    onerror?: OnError;
};


export default function connectSSLNetworkPipe(options: CreateSSLNetworkPipeOptions): Promise<NetworkPipe> {
    return new Promise<NetworkPipe>((resolve, reject) => {
        const sslPipe = new NrdpSSLNetworkPipe(options, (error?: Error) => {
            if (error) {
                reject(error);
            } else {
                resolve(sslPipe);
            }
        });
    });
};
