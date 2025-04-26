
rule TrojanDropper_Win32_Microjoin_gen_B{
	meta:
		description = "TrojanDropper:Win32/Microjoin.gen!B,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 04 00 00 "
		
	strings :
		$a_02_0 = {6a 0a 58 6a 04 59 60 57 e8 ?? ?? 00 00 95 8b 55 3c 8b 74 2a 78 8d 74 2e 18 ad 91 ad 50 ad 03 c5 92 ad 03 c5 50 8b f2 ad 03 c5 33 d2 c1 c2 03 32 10 40 80 38 00 } //10
		$a_00_1 = {b9 2c ff e6 7a 2a c6 38 1a bb 75 14 bb f1 af 8a 95 dc 29 b9 09 ad 59 12 09 d0 f6 c2 45 c5 d8 58 7b 2a 46 49 1b 3f f4 60 71 52 9f 78 6a 9d eb 06 9a 56 4e d2 38 d9 18 a7 } //1
		$a_00_2 = {bf ef 10 80 7c 00 15 f7 bf f0 13 f7 bf 70 3c f7 bf 20 3d f7 bf 20 3f f7 bf a0 3f f7 bf 40 2e f7 bf 70 2d f7 bf 70 14 f7 bf 90 1c f7 bf a2 16 45 77 e0 33 f7 bf b0 17 f7 bf 60 15 f4 77 f3 13 f4 } //1
		$a_02_3 = {8b 73 68 ff 53 54 eb 13 ff 53 20 eb 0e ff 53 14 eb 09 8b ?? ?? 58 5a 50 52 ff d1 80 7d 00 00 } //1
	condition:
		((#a_02_0  & 1)*10+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_02_3  & 1)*1) >=11
 
}