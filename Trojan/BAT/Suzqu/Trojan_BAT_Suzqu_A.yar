
rule Trojan_BAT_Suzqu_A{
	meta:
		description = "Trojan:BAT/Suzqu.A,SIGNATURE_TYPE_PEHSTR,1e 00 1e 00 02 00 00 0a 00 "
		
	strings :
		$a_01_0 = {0a 16 0b 2b 0e 06 07 06 07 91 1f 1a 61 d2 9c 07 17 58 0b } //14 00 
		$a_01_1 = {4d 69 63 72 6f 73 6f 66 74 20 44 65 66 61 6e 64 65 72 20 4c 61 62 } //00 00  Microsoft Defander Lab
		$a_01_2 = {00 5d 04 00 00 62 c4 03 80 5c 31 00 00 63 c4 03 80 00 00 01 } //00 2e 
	condition:
		any of ($a_*)
 
}