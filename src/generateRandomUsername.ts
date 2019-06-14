/** Generates a random username without the letters l, o and w */
export function generateRandomUsername(length = 5) {

    const characters = "23456789abcdefghijkmnpqrstuvxyz";

    let bytes = crypto.getRandomValues(new Uint8Array(length));
    let result = "";

    for (var i = 0; i < length; ++i)
        result += characters.charAt(bytes[i] % characters.length);
    
    return result;
}