
rule Trojan_BAT_zgRAT_A_MTB{
	meta:
		description = "Trojan:BAT/zgRAT.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 02 00 "
		
	strings :
		$a_03_0 = {00 00 0a 0b 06 16 73 90 01 01 00 00 0a 73 90 01 01 00 00 0a 0c 08 07 6f 90 01 01 00 00 0a 07 6f 90 01 01 00 00 0a 0d de 90 00 } //01 00 
		$a_01_1 = {47 65 74 44 6f 6d 61 69 6e } //01 00 
		$a_01_2 = {57 69 6e 64 6f 77 73 46 6f 72 6d 73 41 70 70 31 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //00 00 
	condition:
		any of ($a_*)
 
}