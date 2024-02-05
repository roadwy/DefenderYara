
rule Trojan_Win32_SmokeLoader_QAC_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.QAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8d 1c 0e c1 e9 05 83 3d 24 9f 2d 02 1b 89 44 24 10 8b e9 75 0a ff 15 44 10 40 00 8b 44 24 10 03 6c 24 20 c7 05 90 01 04 00 00 00 00 33 eb 33 e8 2b fd 8b d7 c1 e2 04 89 54 24 10 8b 44 24 28 01 44 24 10 81 3d 90 01 04 be 01 00 00 8d 1c 3e 75 90 00 } //01 00 
		$a_03_1 = {50 6a 00 ff 15 90 01 04 8d 4c 24 78 51 6a 00 ff 15 90 01 04 33 f3 31 74 24 10 8b 44 24 10 29 44 24 14 8d 44 24 18 e8 90 01 04 ff 4c 24 1c 0f 85 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}