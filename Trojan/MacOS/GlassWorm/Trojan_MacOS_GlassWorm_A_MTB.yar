
rule Trojan_MacOS_GlassWorm_A_MTB{
	meta:
		description = "Trojan:MacOS/GlassWorm.A!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {72 75 73 74 5f 69 6d 70 6c 61 6e 74 2f 74 61 72 67 65 74 2f 72 65 6c 65 61 73 65 2f 64 65 70 73 2f 6c 69 62 72 75 73 74 5f 69 6d 70 6c 61 6e 74 2e 64 79 6c 69 62 } //1 rust_implant/target/release/deps/librust_implant.dylib
		$a_01_1 = {e0 ef c4 3d e1 f3 c4 3d e0 77 84 3d e1 7b 84 3d e0 fb c4 3d e1 f7 c4 3d e0 83 84 3d e1 7f 84 3d e0 df c4 3d e1 e3 c4 3d e0 67 84 3d e1 6b 84 3d e0 eb c4 3d e1 e7 c4 3d e0 73 84 3d e1 6f 84 3d e0 db c4 3d e1 d7 c4 3d } //1
		$a_01_2 = {28 00 80 52 a8 e2 0f 39 ea 07 40 91 4a 41 28 91 48 31 40 b8 48 71 05 b8 e8 13 5a b9 e8 67 1a b9 f4 a3 0f 91 80 82 c9 3c 40 0d 80 3d e8 4b 42 f9 e8 2b 0d f9 e9 67 5a b9 a9 03 13 b8 49 71 45 b8 ea 07 40 91 4a 21 38 91 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}