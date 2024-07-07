
rule Trojan_Win64_CobaltStrike_ABA_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.ABA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 44 24 10 03 c8 b8 53 2e 97 a0 f7 e9 03 d1 c1 fa 0e 8b c2 c1 e8 1f 03 d0 48 90 01 04 69 d2 06 66 00 00 2b ca 03 cd 4c 63 d1 89 8c 24 90 01 04 41 0f b6 0c 02 b8 53 2e 97 a0 03 0c 24 f7 e9 03 d1 c1 fa 0e 8b c2 c1 90 00 } //1
		$a_00_1 = {49 03 c0 46 0f b6 04 18 48 8b 44 24 28 49 03 c2 42 0f b6 0c 18 b8 53 2e 97 a0 44 03 c1 41 f7 e8 41 03 d0 c1 fa 0e 8b c2 c1 e8 1f 03 d0 69 d2 06 66 00 00 44 2b c2 49 63 c0 48 03 44 24 38 48 03 44 24 48 48 03 44 24 58 48 03 44 24 68 42 8a 04 18 30 04 1f ff c7 48 83 ee 01 0f 85 0f } //1
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1) >=1
 
}