Implementation of various password-cracking techniques in Python and C.

Task 1: Brute-force Cracking
Implement in Python an algorithm that searches for hashed passwords by brute force. The input should be a list of hashes. The output should be the corresponding list of passwords. You can assume that the password characters `a’ to ‘z’ (lower-case) and ‘0’ to ‘9’. Use Shortlex order to ensure that you cover every possibility.

Demonstrate by finding the passwords that generate the list of hashes:
`['594e519ae499312b29433b7dd8a97ff068defcba9755b6d5d00e84c524d67b06',
'ade5880f369fd9765fb6cffdf67b5d4dfb2cf650a49c848a0ce7be1c10e80b23',
'83cf8b609de60036a8277bd0e96135751bbc07eb234256d4b65b893360651bf2',
'0d335a3bea76dac4e3926d91c52d5bdd716bac2b16db8caf3fb6b7a58cbd92a7']`

Task 2: Dictionary Cracking
Implement in Python an algorithm that searches for hashed passwords using a dictionary attack. The input should be a dictionary and a list of (unsalted) hashes. The output should be the corresponding list of passwords. You can use the password dictionary from reference 3 below. Your solution for this task should avoid re-computing the same hash twice. You should assume that there are no repeated words in the dictionary and no repeated hashes in the input list of hashes.

Demonstrate by finding the passwords that generate the list of hashes:
`['1a7648bc484b3d9ed9e2226d223a6193d64e5e1fcacd97868adec665fe12b924',
'8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918',
'48054a90032bf1348452fd74f3500ef8d2318d9b5582b07449b3b59db841eecd',
'09537eae89936399905661760584b19f6ff3af4bb807cee0bb663f64b07eea8e',
'e7798dc61be73b717402d76cbfaaef41c36c85c027a59abd74abbc8c8288bd4f',
'0f42bcbeedf89160a6cf7ccafe68080f2aafb73b3ef057df6b5e22f1294d0a10',
'13989fe9c124d4dfca4e2661dcf8449f49a76fb69f9725612a130622ff3f9bfb',
'd780c9776eb7d602c805af9ed7aa78225b36af0decb6be51045dcbfa661594a3',
'd2d03c10a4f2c361dbeff74dab0019264e37336f9ef04831943d0f07c0ad52c7',
'cbb05a10a2fc5cc96ce5da00a12acc54f594eadb85363de665f3e5dcb81d0e51']`

Task 3: Dictionary Cracking with Salts
Implement a dictionary search for salted hashes. The input should consist of the dictionary and a list of pairs, where each pair consists of a salted hash and the corresponding salt (in the usual way). The output should be a list of passwords.

`[('915edb4d39ab6d260e3fb7269f5d9f8cfba3fdc998415298af3e6eb94a82e43e','27fb57e9'),
('5ddce1dc316e7914ab6af64ef7c00d8b603fac32381db963d9359c3371a84b3a','b7875b4b'),
('7e3b02bacd934245aa0cb3ea4d2b2f993a8681a650e38a63175374c28c4a7d0d','ec13ab35'),
('d3136c0cb931acc938de13ed45926eb8764f9ea64af31be479be157480fd3014','29b49fce'),
('3a9053a077383d11f5963ef0c66b38c7eb8331cdb03bbdcc0e5055307f67331b','acdabf8a'),
('59c05d8d7b6d29279975141f7329cd77a5dc6942b036f9dfd30cbcb52c320cb4','64afe39d'),
('c93802a2273a13c2b8378f98dda9f166783cbfce508aeaf570ad0b19a906b4d2','f0919683'),
('e6a9713791c2ffeddbf6c6c395add47e1fc02ae1fa47febbbdfb694ed688ba61','081b2451'),
('e6ec51a2ef933920ac1e6d3d8ba6ffac77fe94bfb79518b03cd9b94a14e97d3e','defb64a3'),
('fbecd00c62b01135f9e588883e80f2710a354c0eb73a33a2c5ab5602cc85f6ad','017bb5b7')]`

Task 4: Re-implement in C and compare performance, with graphs and statistics
