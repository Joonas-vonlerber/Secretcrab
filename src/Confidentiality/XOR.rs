fn use_xor(message: &[u8], key: &[u8]) -> Vec<u8> {
    match message.len() >= key.len() {
        true => message
            .chunks(key.len())
            .flat_map(|chunk| {
                chunk
                    .iter()
                    .zip(key.iter())
                    .map(|(byte1, byte2)| byte1 ^ byte2)
                    .collect::<Vec<_>>()
            })
            .collect(),
        false => key[0..message.len()]
            .iter()
            .zip(message.iter())
            .map(|(byte1, byte2)| byte1 ^ byte2)
            .collect(),
    }
}

// Break into pieces of keysize
// do stuff for each of them
// take the piece and combine the key and the piece with the xor operator and make a new list out of it
// collect all of the lists and flatten them into one big list

#[test]
fn xor_test() {
    let yass: [u8; 4] = [0b00001111, 0b11110000, 0b00110011, 0b11001100];
    let queen: [u8; 1] = [0b01010101];
    let expected: Vec<u8> = yass.iter().map(|byte| byte ^ queen[0]).collect();
    assert_eq!(use_xor(&yass, &queen), expected)
}

#[test]
fn xor_test_not_evenly() {
    let yass: [u8; 4] = [0b00001111, 0b11110000, 0b00110011, 0b11001100];
    let queen: [u8; 3] = [0b01010101, 0b10101010, 0b01010101];
    let expected: Vec<u8> = vec![
        yass[0] ^ queen[0],
        yass[1] ^ queen[1],
        yass[2] ^ queen[2],
        yass[3] ^ queen[0],
    ];
    assert_eq!(use_xor(&yass, &queen), expected)
}

#[test]
fn xor_test_strings() {
    let message = b"hei, mita kuuluu";
    let key = b"moromoroo";
    let expected: [u8; 16] = [
        0x05, 0x0a, 0x1b, 0x43, 0x4d, 0x02, 0x1b, 0x1b, 0x0e, 0x4d, 0x04, 0x07, 0x1a, 0x01, 0x1a,
        0x07,
    ];
    assert_eq!(use_xor(message, key), expected)
}
