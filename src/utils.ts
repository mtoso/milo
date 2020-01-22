export function headerValue(headers: string[], header: string): string
{
    const lower = header.toLowerCase() + ": ";
    for (let i=0; i<headers.length; ++i) {
        const h = headers[i].toLowerCase();
        if (h.lastIndexOf(lower, 0) === 0) {
            return headers[i].substring(lower.length);
        }
    }
    return "";
}

export function assert(condition: any, msg?: string): asserts condition
{
    if (!condition) {
        // @ts-ignore
        if (typeof nrdp !== 'undefined') {
            // @ts-ignore
            nrdp.assert(condition, msg);
        } else {
            // node
        }
    }
}
