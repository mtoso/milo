import Platform from "../#{target}/Platform";
import { assert, escapeData } from "../utils";
import { ErrorCode, OnError } from "../types";

export class ChunkyParser {
    private buffers: Uint8Array[] = [];
    private offset: number = 0;
    private dataNeeded: number = -1;
    private available: number = 0;
    constructor() {
    }

    feed(data: ArrayBuffer, offset: number, length: number): void {
        Platform.assert(this.onchunk, "Gotta have an onchunk");
        this.buffers.push(new Uint8Array(data.slice(offset, offset + length)));
        this.available += length;
        this._process();
    }

    dump(): string {
        let str = "";
        for (let bi = 0; bi < this.buffers.length; ++bi) {
            const idx = bi ? 0 : this.offset;
            str += escapeData(this.buffers[bi], idx);
        }
        return str;
    }

    private _process(): void {
        while (true) {
            if (this.dataNeeded == -1) {
                if (this.available > 2) {
                    let lastWasBackslashR = false;
                    let consumed = 0;
                    let str = "";
                    for (let bi = 0; bi < this.buffers.length && this.dataNeeded === -1; ++bi) {
                        // Platform.trace("shit", bi, this.buffers.length);
                        let buf = this.buffers[bi];
                        // Platform.trace("this is", buf, Platform.utf8toa(buf));
                        for (let i = bi ? 0 : this.offset; i < buf.byteLength; ++i) {
                            // Platform.trace("looking at", i, bi, buf[i], String.fromCharCode(buf[i]), str);
                            ++consumed;
                            if (lastWasBackslashR) {
                                if (buf[i] === 10) {
                                    const len = parseInt(str, 16);
                                    if (isNaN(len)) {
                                        if (this.onerror)
                                            this.onerror(-1, "Failed to chunky parse [" + str + "] " + len);
                                        return;
                                    }
                                    this.dataNeeded = len;
                                    // Platform.trace("got len", len, "for", str, consumed + "\n" + this.dump());
                                    this._consume(consumed);
                                    break;
                                }
                            } else if (buf[i] === 13) {
                                lastWasBackslashR = true;
                            } else {
                                lastWasBackslashR = false;
                                str += String.fromCharCode(buf[i]);
                            }
                        }
                    }
                }
                if (this.dataNeeded === -1)
                    break;
            } else if (!this.dataNeeded && this.available >= 2) {
                this._consume(2);
                const buffer = this.available ? this._extractChunk(this.available) : undefined;
                Platform.assert(!this.available, "Nothing should be left");
                Platform.assert(!this.buffers.length, "No buffers here");
                if (this.ondone)
                    this.ondone(buffer);
            } else if (this.dataNeeded + 2 <= this.available) {
                const chunk = this._extractChunk(this.dataNeeded);
                // Platform.trace("extracted a chunk", Platform.utf8toa(chunk));
                this._consume(2);
                this.dataNeeded = -1;
                if (this.onchunk)
                    this.onchunk(chunk);
            } else {
                break;
            }
        }
    }

    ondone?: (buffer: ArrayBuffer | undefined) => void;
    onchunk?: (chunk: ArrayBuffer) => void;
    onerror?: OnError;

    private _consume(bytes: number): void {
        Platform.assert(bytes <= this.available, "Not enough bytes to consume");
        // Platform.trace("consuoming", bytes, "from", this.buffers, this.available);
        let consumed = 0;
        while (consumed < bytes) {
            const bufferAvailable = this.buffers[0].byteLength - this.offset;
            if (bytes - consumed >= bufferAvailable) {
                this.buffers.shift();
                this.offset = 0;
                consumed += bufferAvailable;
            } else {
                const wanted = bytes - consumed;
                this.offset += wanted;
                consumed += wanted;
                Platform.assert(consumed === bytes);
                break;
            }
        }
        Platform.assert(consumed === bytes, "Bytes should be nothing by now " + bytes + " " + consumed + " " + this.available);
        this.available -= consumed;
    }

    private _extractChunk(size: number): ArrayBuffer {
        Platform.assert(this.available >= size, "available's gotta be more than size");
        // grab the whole first chunk
        if (!this.offset && this.buffers[0].byteLength === size) {
            this.available -= size;
            const ret = this.buffers.shift();
            assert(ret !== undefined, "Must have buffers");
            return ret;
        }

        const ret = new ArrayBuffer(size);
        let idx = 0;
        while (idx < size) {
            const buf = this.buffers[0];
            const wanted = size - idx;
            const bufferAvailable = buf.byteLength - this.offset;
            if (bufferAvailable > size - idx) {
                Platform.bufferSet(ret, idx, buf, this.offset, wanted);
                idx += wanted;
                this.offset += wanted;
                break;
            } else if (this.offset) {
                Platform.assert(bufferAvailable <= wanted, "foo");
                Platform.bufferSet(ret, idx, buf, this.offset, bufferAvailable);
                this.offset = 0;
                this.buffers.shift();
                idx += bufferAvailable;
            } else {
                Platform.assert(bufferAvailable <= wanted, "bar");
                Platform.assert(!this.offset, "zot");
                Platform.bufferSet(ret, idx, buf);
                this.buffers.shift();
                idx += bufferAvailable;
            }
        }
        Platform.assert(idx === size, "We should be done now");
        this.available -= size;
        return ret;
    }
};
