use cairo_verifier::{
    air::{
        constants::{CONSTRAINT_DEGREE, N_CONSTRAINTS, MASK_SIZE}, public_input::PublicInput,
        traces::traces_commit,
    },
    channel::channel::{Channel, ChannelTrait}, common::powers_array::powers_array,
    domains::StarkDomains, fri::fri::fri_commit,
    stark::{StarkUnsentCommitment, StarkConfig, StarkCommitment},
    proof_of_work::proof_of_work::proof_of_work_commit,
    table_commitment::table_commitment::table_commit, oods::verify_oods,
};


// STARK commitment phase.
fn stark_commit(
    ref channel: Channel,
    public_input: @PublicInput,
    unsent_commitment: @StarkUnsentCommitment,
    config: @StarkConfig,
    stark_domains: @StarkDomains,
) {
    // Read the commitment of the 'traces' component.
    let traces_commitment = traces_commit(
        ref channel, public_input, *unsent_commitment.traces, *config.traces,
    );

    // Generate interaction values after traces commitment.
    let composition_alpha = channel.random_felt_to_prover();
    let traces_coefficients = powers_array(1, composition_alpha, N_CONSTRAINTS).span();

    // Read composition commitment.
    let composition_commitment = table_commit(
        ref channel, *unsent_commitment.composition, *config.composition,
    );

    // Generate interaction values after composition.
    let interaction_after_composition = channel.random_felt_to_prover();

    // Read OODS values.
    channel
        .read_felts_from_prover(
            array![
                0x3b844d8df7b26d71ddac95a77283731a044d0817799b93504c961643e7536fa,
                0x6eb1a5ad1749834b2625684ee4f1fe4cdff6a2bef8433e7e4f0796d10c80cbd,
                0x75dc13b4e8e554286a11e29269191a31454de9dd8bd1ff74453d3c8282b9c3e,
                0x5d91e860db3002e93c93ded748b5c69b806914610831b81772a7c3c8582b492,
                0x41e5b0b819808f3ee71e801dddd9332ce4bfe3344e1c4a1f98ef7bcc175a654,
                0x68e0292ec793161aaca50432a7eff9844958933f3d1f0ef42ab4d59602eead2,
                0x12ed5ff38e0af36126ae3dad7f8c9324b6295a4b5575332f1654b0eb5f2ba9f,
                0xe748c2e562defed30bd2a97ddf372f8cdff72050ef2fb6d198ec7e26393030,
                0x7f7703acf716b8a8baeea525fd786e6d758499c15543acc9b8b2543d4e9dc97,
                0x606233fd51fb776eb76395b33de0e5b66363061ea0686173b7f2bd51120ecb9,
                0x5aa88ea353d5bcbdcd25060e4dc1f543b5f517b13ded7be39f86f4588184f95,
                0x696e7876c8317fc8c1b64ecd268bca82152ac03e1d67ecf85c58fdd27472eaa,
                0x229795a82fc1785c5d1bcefc966d2d4327ffcf405a2fadedf006d6efe8f5d28,
                0x5dbc9dfb4b87deeb82f1c989dab28eb8238bba970ac6d790bd2bd747150dded,
                // 0x7dbf60320086c11016809745ab2aca3e78a857cc77adaa157f39e73cebd40ec,

                
                // 0x7683f9ad2d57da120622c1831d2f2bc2a21c6c89db08a8dc99e4e2cb4db0a8a,
                // 0x240d9b78177254aa4901e4d020c99f3f8c83800c46645c0d98781c89a889d9a,
                // 0x63d07342b1248a884ed81d8ff276960982f30412232b5eb0e82bd2fee795dba,
                // 0x138b1c827c50360ee6044e071af128a59244515e6f0d25711520cdcc73137ef,
                // 0x3ef3ea7d0ed81a0fb837e9d978cafb1d50d9ff20eb0177cf67eefbf5e094c77,
                // 0x644e69300f7345d84329457a43b888423a3d465b303078ad97694882347a708,
                // 0xc3ba2e34998f165a1e9b6d39e326b840b9624455617ed6b3ab6797e79e7caf,
                // 0x7dcff7dd27d1406d84e194d2a4a514375844327f4657f81c57c0a9780bdec7e,
                // 0x5a7f0e7321ed0fd6002caa89e847e828625862739631c23eeb6b1608a6877e8,
                // 0x7ec3aa585e55878ec09fc43a4c27fa9c6e1650e3a5f40a3f068a8c1edac55cf,
                // 0x4485c63701197e83d82abc2005661d9caaaf16d06f79b554e8497343704650f,
                // 0x7a5547e58a3c521e3f1aa05f9fe92ec5b67acf8160412ea40b124cd6abb409a,
                // 0x61edcece581dfc7c362d5c68413a318a2a13067056735b6f25efa234a8de781,
                // 0x52d5c55126361364bc851e93109aa850fa97b3c52ff2037943b286ee6945f24,
                // 0x1874dc6edd4f2907f6d7853dd484138a1ff5dd970345616637b178180f72016,
                // 0x5c13969e0080179173365d04a5291827a1867b9bb741bfc79fdeb18bdb127b,
                // 0xc313755e3efe95b1719e3673079bb9a8e65abc715f4272c0ec82b05576a5d4,
                // 0x70c40cd969fbb58e0ce8fb8156e75ec643198f1655756dd4345731bdda82457,
                // 0x1ed92b204747f07d2d7d71b6b0c2c714deffd15630dded2baa4e3cd91d6a6,
                // 0x207b8a3383d80b4e472b398348aed1c1d5d297a9f65ae3dcae1db0d6759b2c4,
                // 0x54e9862b9031fc989203051d100afac6f79ca47b45b9a8dc7a489631098bc57,
                // 0x58bcee8afb1cfa88accd584055bbd789dc3ae2078bc24b707a3cbf3d0b406a,
                // 0x3db80e4ef29231ced584222388716ae2f1fe22a2ee2b0e78d7eec08a2fcc617,
                // 0x372efeacd11ce8c0baa8181fac21e3a0b81bdbcbe9804fb049b049b157aab3c,
                // 0x44cf712a574df01e17dadb8536051e939243d5a09653783fa8df7a2340bb0c7,
                // 0x572b6bfa27ee798bc99814d57c0e3a6a3c1271ae0a15f21cfc879bbb0e1447c,
                // 0x659e7542be990fd7964775bbb4ffd6312da031a8a75f58619b9fbcbb45ab862,
                // 0x307c0e7fb6099f26ab78a02fec97a50ccc5af6f3352b06f95b983bd7d42216f,
                // 0x4f3181ab68c2bfeed59c6581be75f03ceb1f75643627f31c0fbeedf86f42eb5,
                // 0x19425c4b4d24775ec1d7af92a56152108b62cbb132dee8d55cf57abbe7fbefa,
                // 0x4fd54238eb975cbc26dc0df31fbf9578f4343910edaba2763dcc0504ee34ccf,
                // 0x6d948775eef790de896d9a2398764cce026083b1230727fb9d0ab1ded7f4078,
                // 0x521fe547fd42527e366950ce2e03049be2af52f8014dda1c8c26726c07da0b6,
                // 0x79ba9a8b07219cbbdadcc343a88ae06619214a2d889a4288e3803a16d9fa8d0,
                // 0x4c02186dfe672284ecb4debe18262098a3d4da503fe0a3faba3b6a1b9cb24a0,
                // 0x169cba5fc545966849d5ca4a04c6543274d8ce2062bac7b031905a236d34947,
                // 0x5ca15ebaa6a4cabcd2ff1b57104f6016078caa2b7b75359f6dcd6768e20ffed,
                // 0x6eebdabdc4004547e4d0b3498e482206e0b53aef4173833cdb9604206df874b,
                // 0x73a44590298020a85aad91f4c24dc904858af2a4cb6db5deb48e08737cb6cd8,
                // 0x2b730dea711f9e6c71bba2dc6f98a44f8b44ca7ada4def018e19d68523345a4,
                // 0x60b9f200e5d6716a88a77906875f3e3bf36b72ce5f68d7daf71779e6b605768,
                // 0x62d04931b023c1589b34cae1fb6deb5cfe9e94e1dc55d37dd75b6a3e7422888,
                // 0x7cf7edb764e6c56c696a0a309825da406c5544f59a312c5be93b0af3f7b7b92,
                // 0x1ff628b40a85fec511117f3b16dd2e4d85a736a27d0d7f3c522c0f4d12237eb,
                // 0x531a594ceb7df07524258e025744818b45172044f4630da3af2dd204e45705f,
                // 0x6cde7377d376d15ddd1644a4f0a01abd299b014a9d6b371be51bb693e47fba,
                // 0x27fdaea9d45e8b4736145c45a1e6f28376aad57522e9db7d2c82b437aef410,
                // 0x511cd012f11b52ff77b3176aa6989c1e3717134dbaf4ba25d1ecfddae6d1dd3,
                // 0x6f4db519f699a96f0d7c31aed14fa67e5b4cf512b41a188dfd05ef2516d22fb,
                // 0x383f290213017ea0c013f1f6f017313484607d086b1d532cfb01c75fa62bfdb,
                // 0x63035854e7a9ece60ec27e05ee24b3e8e33fcd66f69f74072029c7cf888a708,
                // 0x69687f44312ff1c549e15f217d7a05f5d8b730cf6ba2f0b79469ea2aab44fd2,
                // 0x62d482089605df042e99352b47cb7b0b5745ef70f10ded966e8a2d870af38ca,
                // 0x6becfa5e1ecf7017ffbc3dd18d59f2c35918bbebb03a8e733bd8e6a8e5a7153,
                // 0x2dfdf010e2d014f0a2a0ddd980cf270538d4821737c7cffd5ae35879627c035,
                // 0x93732663ebed60e68ede807f8c0376e38e093cbdce185e0e59470aac5b90ef,
                // 0x980b7aa5e884a1d9d06c64c3529d7c4f8cd82344f57c58fb8f33e083379005,
                // 0x7a01e04e34a5e2d6e1b81e433236a3c997933bd4e24329f2632eab796d14993,
                // 0x407cd2e7882070607f7ac384adb97013b42140e2e86be3851c09e38185911a7,
                // 0x7c96759b0eefa2ba71c5a83cd18aee4163f1823bfa56703b790c6107dbf8d55,
                // 0x5f8b457e268f2c4cdd19e4cfee839de5d54263ca574a2a2c1a8a0fde6f680b1,
                // 0xe45237d0e9527b8349ac30395b8b4edb39e9828b377a69fd1b028d127bc3cf,
                // 0x4eb254a9333589162bdec968e7342ce56733d0cc3d1119414a38a8ef38f052a,
                // 0x7c1ebdacaa499725b5b5066ae78dc73a730b6941aa5f89d9f064af4ead97294,
                // 0x5ecbbeb0fd4df85b7a97cc1192dd59dfc5b483cd0d230274cc04e5ca063ca3a,
                // 0x6fd5f158bdb22d4ba47967fce9032e20bdafc7f98a58620aa66a69f651be44f,
                // 0x17a5acc1b4c2f74c9b7b21873837bfe355edc63b70aa7c748eee11d8de9f646,
                // 0x1c111d2c257fb6a6fb826ead1f994971f528105bb2fd04b339759f5199f96ba,
                // 0x51aaf4b65bfc8dace07fde3f9ea5966848a1c7ef96ac91dffbe3c6ecf39cec1,
                // 0x5e33e6e50fa05337c6aaf111d3371a5869d1f3e418e84a8b92f9f6789bd6a98,
                // 0x49ba34c8cbdc2818f4f09c4ca7484d9a0a2c7f8bce743f08ceac127dd17fbdb,
                // 0x34b1417dd68894b89cfff52f89642bda9524de53e4fa22103aa3ee7f00366fb,
                // 0x7664cbf6da8ad539b0b9ed7b9a86b06cc5f80f639e995c0973e285efdb779a8,
                // 0x3108e8a3aa756c138343ae9a9676ed77f5e3da60cf519fe2863baf9f114c004,
                // 0x371568ef4831cfff4baeeaa9142f749596b68202c3500fab27993fab77f94bb,
                // 0x2013ab48977221f9b9861e0d721f563f7853c20222560ead2717f1d668d8e7c,
                // 0x67b389022e2e540b2cb55ebee82d08b218e186c7169d8a4b99815ef7088738,
                // 0x275d7eb58495f33c3e03a327146743ffe91eed27b0c7c3501b2c50e0a166ad5,
                // 0x2cb9eb5d9cbe6495c048aa1eb6faf9f5c0246853832135009cbbec955027bf3,
                // 0x635663b9e2ef0c57ae830064f0bece8f18d3276f6dd1242a91ed45f067918ce,
                // 0x73a0767432cddef3e0654942d64bb8b4802334b795250ae4ebbf84200cd226,
                // 0x65ee582c948b8c4ae64b2eb31affce5771d3fb6437d60e7e5669a0a12f59d21,
                // 0x1ebb003fedab8cebd11c4e7fedffa3937e5888e1be2bf90b163c5392c6d00b1,
                // 0x25a290f232a1bafb1c97efbfb4a5a7f6a2c2023b1ab3344b44ccca30f514eb4,
                // 0x473aaf24106c820bf7a87d8e781626b0a534d674ed814df151ad31c1a7a2c4e,
                // 0x4fd4711443d02452732fe7304ed5367472b24a37404d4203e552699df38e1e4,
                // 0x27fca6dd6064dcadf604a7cd878dd6591c2eceacef36ac0f64bcdf8d50bc143,
                // 0x51186a24a0768ddec0a2ab60164139499df0022ceab15e480fae9e3678f8a68,
                // 0x7c563abd1420f288bf0b7dfb184af9c8c24017fe652d9e58d8caa3784b445cc,
                // 0x2a7dff406b5c7b8e910676df491ce42202a037b4b1129b243040fa99a05a81a,
                // 0x6f8512bf92c7b4a875abb184a245db46fd43cd2908ce912bda10762fd337d50,
                // 0x51530afb2758fa99dafe378aaa89493d8631de864f53f3d423396ba2fc165c7,
                // 0x39fe7a0520ea8d4dba51062dee07750a1b77a3e28dc7374f66c6eee8ac846ff,
                // 0x6e1f1cd0082420e0c59b2d12d972dfe1d943d66670d4abdd355ce036382a691,
                // 0x11aad3cdaba675421e2b3fba375eb2687306e6742cca1d03fe3371a1df217b5,
                // 0x7722d41c190586dbc84ec13fdd5ec42d7702f158bc1cc29f08ef3ed19ac862f,
                // 0x449eca9e55b688a369bf360d6096751456a33168c9ec38e986447c9895ef98,
                // 0x65339aa37351112d383def9d140b3602cb88bb9decda842fdf1208a6a7f0a4d,
                // 0x6630d06f5c63e320deafd2c6a4cc5bffbfddb614d347bf1d607d983d404f0b5,
                // 0x1a4913a89f0fadaf62bd689eec4e9edb14213aaebfc307aa591c916c54b830a,
                // 0x3a79548f79577c04dd286ad1db64b38dbf32f9b6fa937168c46d2e98dd76d32,
                // 0x283055e9bf6b05db39cce849f8a6be5419b1ee2106316967b1514f5bea44c45,
                // 0xf88adab6614d6d445db04fc7cad589cc19a67d6ba3500f64c3effcecfab112,
                // 0x47c09554878d8fc2afcfa0b136cc3adc102cd6c790b7cfcbd4cc33932a720e,
                // 0x4c9be49cff06dd947e1f8016f0e65ca839201072bb0ecf54f4e49023d2ca878,
                // 0x3a57b0961dc7b48db58921d1f6532fc6ac7bd73b0713a80074c6f6b78cc7219,
                // 0x7d2e0924dacacd0de5d7cd1d74e357fc90e83b28c964800011c2d3bb39f6ec4,
                // 0x76d089ceb84af74183cf948602f3724a32783a669a61715c12e017ec3eca29,
                // 0x7fa727777d52242828b4e0ac59ccabec6939789e90a6109882b57903cb1a88e,
                // 0x58803b504852d9baae0acea9b94893808f8428d3f1b66fdc3e95b35e9231a3f,
                // 0x32d904eca7ea63e7174ab1f19d0430ca1f8daddf03c7b400cee6380c4f4cd8,
                // 0x5dfb739807b4cb1fe4387475630c52f0b44a2f92bdc2718e872273c4b4fa013,
                // 0x733caba128dc8696c58e20e8f451c63dc8711ff6d6e4ec498b5de3b07f0bb47,
            ]
                .span()
        );
// Check that the trace and the composition agree at oods_point.
// verify_oods(
//     *unsent_commitment.oods_values,
//     traces_commitment.interaction_elements,
//     public_input,
//     traces_coefficients,
//     interaction_after_composition,
//     *stark_domains.trace_domain_size,
//     *stark_domains.trace_generator,
// );

// // Generate interaction values after OODS.
// let oods_alpha = channel.random_felt_to_prover();
// let oods_coefficients = powers_array(1, oods_alpha, MASK_SIZE + CONSTRAINT_DEGREE);

// // Read fri commitment.
// let fri_commitment = fri_commit(ref channel, *unsent_commitment.fri, *config.fri);

// // Proof of work commitment phase.
// proof_of_work_commit(ref channel, *unsent_commitment.proof_of_work, *config.proof_of_work);

// // Return commitment.
// StarkCommitment {
//     traces: traces_commitment,
//     composition: composition_commitment,
//     interaction_after_composition: interaction_after_composition,
//     oods_values: *unsent_commitment.oods_values,
//     interaction_after_oods: oods_coefficients.span(),
//     fri: fri_commitment,
// }
}
