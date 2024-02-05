
rule Trojan_BAT_RedLine_MX_MTB{
	meta:
		description = "Trojan:BAT/RedLine.MX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 04 00 00 0a 00 "
		
	strings :
		$a_03_0 = {09 09 06 06 da 17 d6 2e 07 72 53 00 00 70 2b 05 72 2d 06 00 70 6f 90 01 03 0a 00 7e b8 00 00 04 09 17 d6 09 06 06 da 17 d6 2e 07 72 53 00 00 70 2b 05 72 35 06 00 70 6f 90 01 03 0a 00 7e b8 00 00 04 09 18 d6 09 06 06 da 17 d6 2e 07 72 53 00 00 70 2b 05 90 00 } //01 00 
		$a_01_1 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //01 00 
		$a_01_2 = {43 6f 6e 6e 65 63 74 69 6f 6e 53 74 61 74 65 } //01 00 
		$a_01_3 = {66 72 6d 46 65 65 50 61 79 6d 65 6e 74 52 65 63 65 69 70 74 } //00 00 
	condition:
		any of ($a_*)
 
}