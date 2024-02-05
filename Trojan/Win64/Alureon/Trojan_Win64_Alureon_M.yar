
rule Trojan_Win64_Alureon_M{
	meta:
		description = "Trojan:Win64/Alureon.M,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {41 8b 44 24 28 ba 01 00 00 00 48 03 c1 ff d0 85 c0 75 0f 48 8b 4f 18 33 d2 41 b8 00 80 00 00 41 ff d5 } //01 00 
		$a_03_1 = {41 81 7f 18 3c 3c 22 00 75 23 44 88 25 90 01 04 eb 1a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}