
rule Trojan_BAT_IceXLoader_NEAA_MTB{
	meta:
		description = "Trojan:BAT/IceXLoader.NEAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {73 01 00 00 0a 25 28 90 01 01 00 00 06 28 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 28 90 01 01 00 00 2b 6f 90 01 01 00 00 0a 2a 90 00 } //02 00 
		$a_01_1 = {77 00 77 00 77 00 2e 00 66 00 69 00 6c 00 69 00 66 00 69 00 6c 00 6d 00 2e 00 63 00 6f 00 6d 00 2e 00 62 00 72 00 } //00 00  www.filifilm.com.br
	condition:
		any of ($a_*)
 
}