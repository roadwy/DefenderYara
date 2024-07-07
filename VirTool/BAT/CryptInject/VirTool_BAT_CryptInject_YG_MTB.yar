
rule VirTool_BAT_CryptInject_YG_MTB{
	meta:
		description = "VirTool:BAT/CryptInject.YG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {20 f4 01 00 00 28 1e 00 00 0a 07 20 82 44 f9 b1 5a 20 19 a1 90 fe 61 2b aa 06 28 1f 00 00 0a 6f 1a 00 00 0a 07 20 50 5e 3c 75 5a 20 0c 7f 4f c2 61 2b 90 06 6f 20 00 00 0a 2c 08 20 e7 55 2f 31 25 2b 06 20 c2 86 f3 79 25 26 38 74 ff ff ff 28 21 00 00 0a 2c 08 20 90 7d e5 ad 25 2b 06 20 58 64 f0 cb 25 26 07 20 a6 d3 54 d3 5a 61 38 51 ff ff ff 28 22 00 00 0a 2c 08 20 7c 66 33 2f 25 2b 06 20 71 f1 b2 51 25 26 38 36 ff ff ff 14 28 14 00 00 0a 07 20 a8 58 51 df 5a 20 4f 0b 28 cf 61 38 1e ff ff ff 14 28 14 00 00 0a 20 b4 7f 26 49 38 0e ff ff ff 14 fe 06 03 00 00 06 73 17 00 00 0a 73 18 00 00 0a 0a 06 17 6f 19 00 00 0a 07 20 c6 4a 07 b6 5a 20 ed 62 22 d4 61 38 e3 fe ff ff } //1
		$a_01_1 = {14 28 14 00 00 0a 08 20 49 31 12 16 5a 20 fe 45 08 39 61 2b bb 07 2d 08 20 31 e1 b3 a4 25 2b 06 20 09 74 0e 85 25 26 08 20 81 5a e0 0e 5a 61 2b 9f d0 1e 00 00 01 28 15 00 00 0a 72 09 00 00 70 17 8d 06 00 00 01 25 16 d0 20 00 00 01 28 15 00 00 0a a2 6f 16 00 00 0a 0b 08 20 57 2f 6b 75 5a 20 fb fa 77 41 61 38 65 ff ff ff 14 fe 06 03 00 00 06 73 17 00 00 0a 73 18 00 00 0a 25 17 6f 19 00 00 0a 14 6f 1a 00 00 0a 20 ee da 46 c6 38 3d ff ff ff 72 37 00 00 70 07 14 17 8d 04 00 00 01 25 16 06 72 3b 00 00 70 28 1b 00 00 0a a2 6f 1c 00 00 0a 6f 1d 00 00 0a 2d 08 20 1e 59 68 c3 25 2b 06 20 d7 90 72 eb 25 26 08 20 64 d9 1c d7 5a 61 38 fa fe ff ff 2a } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}