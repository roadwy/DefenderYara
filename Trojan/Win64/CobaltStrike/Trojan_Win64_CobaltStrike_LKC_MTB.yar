
rule Trojan_Win64_CobaltStrike_LKC_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.LKC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {49 83 e1 1f 49 83 e9 20 49 2b c9 49 2b d1 4d 03 c1 49 81 f8 00 01 00 00 0f 86 a3 00 00 00 49 81 f8 00 00 18 00 0f 87 3e 01 00 00 90 02 19 c5 fe 6f 0a c5 fe 6f 52 20 c5 fe 6f 5a 40 c5 fe 6f 62 60 c5 fd 7f 09 c5 fd 7f 51 20 c5 fd 7f 59 40 c5 fd 7f 61 60 90 00 } //01 00 
		$a_03_1 = {41 b9 40 00 00 00 41 b8 00 30 00 00 48 90 01 03 30 33 c9 e8 90 00 } //01 00 
		$a_01_2 = {53 64 72 70 73 74 } //00 00  Sdrpst
	condition:
		any of ($a_*)
 
}