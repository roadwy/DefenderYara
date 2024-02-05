
rule Trojan_BAT_RedLine_NZS_MTB{
	meta:
		description = "Trojan:BAT/RedLine.NZS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {03 02 03 6f 90 01 01 00 00 0a 5d 6f 90 01 01 00 00 0a 7e 1a 00 00 04 02 91 61 d2 0a 2b 00 06 2a 90 00 } //01 00 
		$a_81_1 = {4a 4a 34 56 57 51 44 52 53 44 33 55 35 59 56 } //01 00 
		$a_81_2 = {50 4f 52 54 52 41 59 2e 65 } //01 00 
		$a_81_3 = {43 4f 4c 4c 45 41 47 55 45 5f 54 50 2e 50 } //00 00 
	condition:
		any of ($a_*)
 
}