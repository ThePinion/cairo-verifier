use cairo_verifier::vector_commitment::vector_commitment::{
    VectorCommitment, VectorCommitmentConfig, VectorCommitmentWitness, vector_commit, VectorQuery,
    vector_commitment_decommit,
};

fn bench_vector_commitment_decommit() {
    let commitment = VectorCommitment {
        config: VectorCommitmentConfig {
            height: 0xb, n_verifier_friendly_commitment_layers: 0x16,
        },
        commitment_hash: 0x3ce8c532eab6fcbf597abd8817cc406cc884f6000ab2d79c9a9ea3a12b4c038
    };

    //n_columns 0x4

    let queries = array![
        VectorQuery { index: 0x98, value: 0x67406d6bb8db3de41d8b7dd9896c85e6d69e951d },
        VectorQuery { index: 0xa7, value: 0xa04e05c094e8ff020674895a8e87f2e9cfe3bc5c },
        VectorQuery { index: 0xbc, value: 0x1e6d3c0ebe3b5b027d004491854b3f0d65ed3e0 },
        VectorQuery { index: 0xde, value: 0x32c5b2dbb1c4ddf042f28957e05374d52fd89f02 },
        VectorQuery { index: 0x1bc, value: 0x2c9bb403fe8e8bac0653f29385806918bd1fcf0e },
        VectorQuery { index: 0x1c1, value: 0xf56fb4a5d883041b083ed09e0e6716227514cab0 },
        VectorQuery { index: 0x1eb, value: 0x6a61fa5e145d3bb6bc886355e41f07f53deb8866 },
        VectorQuery { index: 0x27a, value: 0x2b42bc4742c6be2f729de5ee226f98a6f1ac7849 },
        VectorQuery { index: 0x300, value: 0x16c6e1dfe9a2861f9e104bddfc080a582e12bf37 },
        VectorQuery { index: 0x3dd, value: 0xbe093d1e5cde50c05c920259ff84bfabf4b3b0a0 },
        VectorQuery { index: 0x41a, value: 0xc7c4b092d8de1c9c0befaaf19ee51fdbe9999245 },
        VectorQuery { index: 0x43f, value: 0xaa42411d4938220290da0c5e6fbcf16cdef04847 },
        VectorQuery { index: 0x48a, value: 0x53cfb0631374186865337530371bc3129da3a418 },
        VectorQuery { index: 0x710, value: 0xbc77966ffc759fbdcf7ff1d5ff9275efb49e61b8 },
        VectorQuery { index: 0x72e, value: 0xaa3cc5a670b9f970f7dac6b7adb3f971456dfff6 },
        VectorQuery { index: 0x751, value: 0x19b79813c4376f363b27a623482a01775a4f7dcc },
        VectorQuery { index: 0x772, value: 0xbbaa216e8f9946749b0325ad463333f411c5ddd3 },
        VectorQuery { index: 0x78e, value: 0xd6ba0eee61fc3a2c0d901e56e5a2539e7c38d1d5 },
    ]
        .span();

    let witness = VectorCommitmentWitness {
        authentications: array![
            0xe676ff357a733da543bb3d81e3aa60ca9f1063e1,
            0xffc663afe730d87e8c5b65ff1c4e02bebfb45c5,
            0x9ee28fd2b364c452dfc86e0fb15db982895abb18,
            0x4b2aea8358aa2562fc75d90ff221cf7643da2d30,
            0xe6ca528ff25b6a8027f6f186a6823b22e407d0f4,
            0x2ffc0ca2d4c2a613decdcee120d7ce8bd31270b3,
            0x87525e0ba3a6d4f8ddf4a7cc48deb7546f12bd80,
            0x26d3a33a07adc85a684d7aa9fdf8b6f582b9acfa,
            0xc65fbd68d029050bd45eb8e111a6f31f87c0b451,
            0xb43296f2dc5b4c4d908b80789b193962be8db556,
            0x9465cacc05be1a69f3eb38424e448a73199774d6,
            0xb48f007b7760a3cc2056e5db6f3eca5c4aaa7c8e,
            0x54f3688454cf9b399bca2139a865ab970b02e0e,
            0xadcfc979b6dd3e142d5c1a6dd2f51d1f65651de1,
            0xaaebcd47fccc02841f65830056d1f2d0075a6d25,
            0xe45f1dd9110a7a0b3a6c157b841fd9aff4e66874,
            0xa3b8e22670e0876ec1f042c974359444c595f1a2,
            0x92693ffbfd0ad1f60d4f8843658f20c54fd11a5a,
            0x7281b36fcfc367c94e83bdb8ea3e08d0142cd0d2fe627b80c73acef7e6a49b9,
            0x3b5e95b9b0fadaf1031300d7c0d9f043706f4dc7f8baff7e2dd55a1a6c65b84,
            0x2cc6a33256646a68bed5dd10cb782b229736fc9028ad7addb3ec487c38e937c,
            0x296e424b9795e3f4f1e5c00d6285afbb4c797c6dd8624fd735824cb9fa8fb04,
            0x36931e8cf7d2e8cae2087d7532f93c12c8ffa20fe5c7a02c9aebd2c0657158,
            0x49c91ee3ddec4f62d4c5dd802317cfe81ba9009e7b46f66bb354019e284194a,
            0x63ed1d118d536eedd9a286f4fc633b7625f8af0a2bdf6acbeb4e7462dcd734e,
            0x4620a4b9fa50fbdd167b899ffa02e8965aa056d35086db2322d6a703c7ad15f,
            0x475db860a575eae6424c0bac0039cd8a9450ea558211e42db402a826c14c1dc,
            0x4c69f749f7b1a98b707ea255d786c43a944031f3bf9d2fdb4f5b1310c61bfa3,
            0x1552bebad7cd328047b44545dfdb3412953d8548b7a65bf15f0f1ccfc98fc0e,
            0x44557ef3c00fc68816781800bcf8ef54d988d70c8d22189bbd0415328c8eda0,
            0x4ac53f19aa2254dc7ce25d541953e31c2c143069760254162227ce3d975b61d,
            0x795b6fcf227eb5d19a4e01c5defc88ba05a65eebf23b9306a7513769d96d040,
            0xdbe8fb2afa68997d0ae59711090a255bfbb5f5ed6543a5655ad79577a7aeae,
            0x785cde61bda7ca4638d7759a0a742942eaedbf08d1269d36f373c3908964a7e,
            0x7f0d790427a3fe91985b625ab9138e5ad2a05af440c26201c516a6ff852f022,
            0x5cfc3623a36de637078f8daee039d624bf693db91f8fdb4ed81a41f59e09f3b,
            0x453ff600781c3bb90b791d0a7537f31add3a733ba5ea5bc9887d4bab9948a05,
            0x26befde2c0f7ad61a726b7138869d76f66ac68e809855fec10bb4e3fc846a0,
            0x7ae21aa0e4e1bd6e63527d34e9d493e6b1943d769c3d970e1a6113fb8cdc509,
            0x3c4bb6412da8c8cd9155cf27a22934afd270ce654486b15cd77813d1973fe7d,
            0x765c40ad58db8cf29235128173ed93490d2fee999353fa4d1401cf734bae9eb,
            0x6a8a36b56c2919a2c0f00485d929009d085c52583868aa96a87574e02ac19cb,
            0x7c606e8d4c7a82c9b97c733908dce06038ab72ce1d70026f1458b8b0840162b,
            0x94922071ef2d6c99fe9da993fa6b494e82a25dc10ab5d6bbbd71b28f58b9c1,
            0x53f5dd1bb156b3744de60903a5e1b89fd202dfd0b1c50279c04894f6ab2d13d,
            0x6768cb453416dfac3b0eebbb53efb0748e27bca54c0e870c58d9a8f869fa036,
            0x16c12fcd3cdafd2f4328fc1a2299de4035baa36fe3bf46701c98558166f9b4d,
            0x29cb2a1d86816e6e5ceacbd12c58088385d111cbec53ab677e38b56c3aeb350,
            0x8247a109564a0dbcc9f7bad00e0f4131bd1c024e0f3b76ebb6b6c66b317b6b,
            0x4751b9f7b400984dbf007960a0522b3696277bea06b4a950ef9b98fe0a8f08e,
            0x22907e920eec443995bc55de7ebafec33320ae4ecd0a3dd8635e95ae3ab52bd,
            0x7f92acf18e809b3d2a25deef9f176cfbcf1cee6dc48ac1bd1ccfb47f3d01a8b,
            0x304fb4d291aa6db2a08cb4fa70e7e3fce26d927048a78a725afcad00eebe671,
            0x7748c9d244881a114b8c225d3dc3c212377013fbe9bb4f681024c94c554350c,
            0x1e6e1c4a459327339e22e2ce13a7e5e8b55023617731712613898f011237ed1,
            0x51344e80e161f57469e4695e624b56c9989ce3fc4081a0a5e2c1e56ff5f4d22,
            0x2d8af710272d1e39b101419c80f691346cc93c4cb41d457dbd6697e09490505,
            0x69ad0f6fbd109ea3547b6606981197b802a920a319c61fa03ebee73c346e9ad,
            0x5c0469ac2a93eb97c7cda4f82253280bd681a611eec612eaff3f91b81844aff,
            0x2022f6794db246316b2d2e024e70008bd6ada94a1958b8e5d5cc039202d9400,
            0x23c4647f032d7703fda9ffbb4c2c983323c11ce80412b2b5e3b20efa4d3062d,
            0x37f277ff3e939433e79e156ce68004fe24741f8c1b9264d346919582117e3d3,
            0x4388f543724d6095d53ce54c2b8fec2df52ed0830cff0df933181fb8e377490,
            0x1f9646a1c35ccf8656ec727053aa7fc6a571ca0498bc22624f3e0dadc2e1bd,
            0xad4cd2d1f4c6da0c831c51b13b8bfe987f61d369f5fa64bfc8827f607c96c6,
            0x636027ef64d2f9ba05b3cf507f840c19f12645fb6a0db2a24b8cf1569191bb6,
            0x43c8814510c36a011f1b1994275a928b66812d7c3ef14d93c31463339137bbe,
            0x300b7133fc0cc085144a2a14e496700dbc4f8b583657ffdde33de02ef78191c,
            0x7ba0d828caa7cb414640e08a2fbd789a8d111ec7883ffab5fd538c120c5a5e6,
            0x8dde3adeb2e83b034a5ccc12638008362a24d66835262ad33caa211a6c9793,
            0x849bf4d63ae4007169c0bd9f5a2b7f572ee2bcd188e868f981b5f4f67bd47d,
            0x3ced5193d4bb228dfa19e7f7d46372d80393b242a72d48262e1a8594f623094,
            0x325ba92845f1d7350fa4491e3405fde9ebda7c1bbbf7e066a2c8c10a6c680c3,
            0x155b15335843b15e4b816ae7e6a340d452d6247552864ac53e39b56910519b4,
            0x482777b78954afd4c3ac5ebb92f93a82af11652f50935960d6ac75f75674140,
            0x6fe0d0ec0abe430cf7c7c32f15a7ae343796f6175e292fed589aea79b813616,
            0x5618be8b708e7ddca48c8b971916c5fd9a1ba6eb4252e614ef88c4f2e41775f,
            0x51365af55597548ba0f4543e4fccba8c6e1a7faf6b2e8c48af96dd16b48e8f1,
            0xb5cce5205193c3b87dafdf96fd0de0cdac974558aa47e18e515841b2740b1d,
            0x51a1cc3992db4da580a2a77277cd81e52376c266b8f8c585b879a2251d7439a,
            0x7ca03ac5453cdeff7d3fb2742680345af326e92935686f84462de6f37588dd1,
            0x3b26307ed64a35759b0b4792c1f74803627c6b31046ed9c8ff9cc9bfc5b2c0,
            0x27a8f5d9f84205f8439338257462f4efaf07924aded94b419ec98c0be0ace0,
            0x42223b23fa282ef6a087a92cc400d36ccc6e8d6d953e6d3144bd2f26505a6f,
            0x4ef7521d71a61c9fc42725fbf3e36361b53046b68694ce437f576d079ce86f5,
            0x35fe0ea431a96210926bbe2002d26c15133a0c2bb1d2c6ee31cec86af66922f,
            0x158bfc28d59e25bf7b7a0e9995d1fe201d708db865013aabd6f19fb371a734b,
            0x46b9fd1bf3be4660e16c85ae8854e2dd6a8d4203d4b19926e66b3a881553b96,
            0x4084cc05bc951721e44cbc69526393ece2f17d2c3ed28675d92bf6e33c1c047,
            0x4b8e7e93f3a6888142902582531d0659329a714727f26fa4bc87e4eafa1077,
            0x2e9e738a183faa18f7bdce422e9f49318226b3b32d1d8410a48b1cab0875c5,
            0x20f4db5c5abe20c948b151cc25bd4c2c001eb8a13711742dc665a21edf137fc,
            0x63b799bbf4ec3241fe16b4a154194ccd9e6377a785527ed9365e725521ae17c,
            0x365b2a7dcd62b7b0dcb2d10167cdd87c4ad1174dea6fac139d54a3256c0c1d8,
            0x3e0bfea95daf7c3a3244e35549f078e029e544b9fe65b4548ec28fe8212b9d,
            0x4a899f49847c782e0dbf581f89aa522e4114b42a741d5d78efbe49808ba91f3,
            0x593e1c4dc6e2ed44e0953cf736581eda4cc6873859f3e1614c629cc58d86689,
            0x12b4960751c2799461bc1fd9e8466c5cc1f2bb4e91aa2be4d7d1c87fb7e3d71,
            0x3e3c1fc87c1b07d5f40b728ea660c6320691a1b596edd70d7a2b48bf8e66d47,
            0x4a0eb250ff1e14199c95f1a942542e0ddb486317de03d033b6b03cf6a1f66e5,
            0x2a768272e178821889693ea00ffca5c5309a7ee33b078a675ff2b4f3dd82325,
            0x364195536f59b340f0f315fec7361229e4a61ae63e77d182dac9d54a2170296,
            0x204636737aef25c5f4c8aa332e67fc3618e83a896f134f10ed929677bba4f7b,
            0x75dfb1d1da06ef149195da6171b78ca57f21946e8920aef4da97c59581fc37b,
            0x74f11bef16a2c8923231df2090b074be1c0b017f7f1f12f919f332c9362f82a,
            0x109604ebb9ecedc292252882c8eb95d3ca041db27cf1d8a76ba6dfc2355a9c9,
        ]
            .span(),
    };

    vector_commitment_decommit(commitment, queries, witness);
}
