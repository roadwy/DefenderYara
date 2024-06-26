
rule Trojan_Win32_DarkGate_AD_MTB{
	meta:
		description = "Trojan:Win32/DarkGate.AD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,65 00 65 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {f1 d5 00 fa 4c 62 cc f4 0f 0b } //64 00 
		$a_03_1 = {8b 44 24 04 90 02 10 8b d7 32 54 1d ff f6 d2 88 54 18 ff 43 4e 90 13 90 02 30 8b 44 24 04 90 00 } //64 00 
		$a_03_2 = {8b 44 24 04 90 02 10 8b 14 24 8a 54 32 ff 8a 4c 1d ff 32 d1 88 54 30 ff 8b c5 90 02 10 3b d8 7d 03 43 eb 05 bb 01 00 00 00 46 4f 90 13 8b 44 24 04 90 00 } //00 00 
		$a_00_3 = {5d 04 00 00 a7 3e 06 80 5c 2f 00 00 a8 3e 06 80 00 00 01 00 2e 00 19 00 42 65 68 61 76 69 6f 72 3a 57 69 6e 33 32 2f 47 6f 6f 74 69 6f 75 73 2e 41 00 00 01 40 05 82 70 00 04 00 b3 ec 00 00 05 04 03 02 00 00 00 00 00 02 40 00 00 58 40 00 17 89 ae 20 df 00 00 00 00 00 00 01 00 00 00 00 00 02 03 49 94 } //32 60 
	condition:
		any of ($a_*)
 
}