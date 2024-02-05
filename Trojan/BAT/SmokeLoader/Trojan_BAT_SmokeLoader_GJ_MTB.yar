
rule Trojan_BAT_SmokeLoader_GJ_MTB{
	meta:
		description = "Trojan:BAT/SmokeLoader.GJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 04 00 00 0a 00 "
		
	strings :
		$a_03_0 = {02 19 1a 2d 16 26 03 1a 1d 2d 13 26 18 6f 90 01 03 0a 1f 10 28 90 01 03 0a 2b 06 26 2b e8 26 2b eb 2a 90 00 } //01 00 
		$a_80_1 = {66 69 6c 69 66 69 6c 6d 2e 63 6f 6d 2e 62 72 2f 69 6d 61 67 65 73 2f } //filifilm.com.br/images/  01 00 
		$a_01_2 = {54 6f 41 72 72 61 79 } //01 00 
		$a_01_3 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //00 00 
	condition:
		any of ($a_*)
 
}