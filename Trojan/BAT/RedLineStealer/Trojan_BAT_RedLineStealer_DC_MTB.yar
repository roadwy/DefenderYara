
rule Trojan_BAT_RedLineStealer_DC_MTB{
	meta:
		description = "Trojan:BAT/RedLineStealer.DC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {16 0b 2b 13 06 07 02 07 91 03 07 03 8e 69 5d 91 61 d2 9c 07 17 58 0b 07 02 8e 69 32 e7 } //01 00 
		$a_81_1 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //01 00 
		$a_81_2 = {2f 63 64 6e 2e 64 69 73 63 6f 72 64 61 70 70 2e 63 6f 6d 2f 61 74 74 61 63 68 6d 65 6e 74 73 2f } //00 00 
	condition:
		any of ($a_*)
 
}