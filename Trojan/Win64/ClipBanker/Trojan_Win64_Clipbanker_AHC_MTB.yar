
rule Trojan_Win64_Clipbanker_AHC_MTB{
	meta:
		description = "Trojan:Win64/Clipbanker.AHC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 03 00 00 "
		
	strings :
		$a_01_0 = {48 8b 85 90 01 00 00 48 63 48 04 8b c7 48 83 bc 0d d8 01 00 00 00 41 0f 45 c7 0b 84 0d a0 01 00 00 83 e0 15 83 c8 02 89 84 0d a0 01 00 00 23 84 0d a4 01 00 00 0f 85 } //5
		$a_03_1 = {8b 45 d0 ff c0 89 44 24 28 48 89 4c 24 20 41 b9 01 00 00 00 45 33 c0 48 8d 15 ?? ?? ?? ?? 48 8b 4c 24 50 ff 15 } //3
		$a_01_2 = {63 6f 73 6d 6f 73 31 64 65 70 6b 35 34 63 75 61 6a 67 6b 7a 65 61 36 7a 70 67 6b 71 33 36 74 6e 6a 77 64 7a 76 34 61 66 63 33 64 32 37 } //2 cosmos1depk54cuajgkzea6zpgkq36tnjwdzv4afc3d27
	condition:
		((#a_01_0  & 1)*5+(#a_03_1  & 1)*3+(#a_01_2  & 1)*2) >=10
 
}