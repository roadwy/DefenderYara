
rule Trojan_Win64_Cobaltstrike_FTL_MTB{
	meta:
		description = "Trojan:Win64/Cobaltstrike.FTL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {41 b9 40 00 00 00 41 b8 00 30 00 00 48 8b 54 24 28 33 c9 ff 15 } //01 00 
		$a_01_1 = {4c 8b c9 49 83 e1 1f 49 83 e9 20 49 2b c9 49 2b d1 4d 03 c1 49 81 f8 00 01 00 00 0f 86 a3 00 00 00 49 81 f8 00 00 18 00 0f 87 3e 01 00 00 } //01 00 
		$a_01_2 = {c5 fe 6f 0a c5 fe 6f 52 20 c5 fe 6f 5a 40 c5 fe 6f 62 60 c5 fd 7f 09 c5 fd 7f 51 20 c5 fd 7f 59 40 c5 fd 7f 61 60 c5 fe 6f 8a 80 00 00 00 c5 fe 6f 92 a0 00 00 00 c5 fe 6f 9a c0 00 00 00 c5 fe 6f a2 e0 00 00 } //01 00 
		$a_01_3 = {75 30 48 39 5a } //00 00 
	condition:
		any of ($a_*)
 
}