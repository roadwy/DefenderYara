
rule Trojan_Win64_Bumblebee_KU_MTB{
	meta:
		description = "Trojan:Win64/Bumblebee.KU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {4c 8b 83 38 03 00 00 48 63 83 d4 04 00 00 48 63 93 d0 04 00 00 48 c7 83 d0 00 00 00 a4 c8 73 01 41 8b 0c 80 41 31 0c 90 8b 8b e4 04 00 00 41 23 cb 7d 07 } //01 00 
		$a_03_1 = {49 8b 4d 18 49 8b 45 30 49 63 95 90 01 04 8a 14 0a 42 32 14 08 49 8b 45 60 41 88 14 01 41 69 8d 90 01 08 41 8b 85 e8 01 00 00 05 7e 01 00 00 3b c1 73 11 90 00 } //01 00 
		$a_00_2 = {48 53 64 4f 74 36 30 33 36 32 } //00 00 
	condition:
		any of ($a_*)
 
}