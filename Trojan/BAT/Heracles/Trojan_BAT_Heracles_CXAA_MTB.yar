
rule Trojan_BAT_Heracles_CXAA_MTB{
	meta:
		description = "Trojan:BAT/Heracles.CXAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {0a 00 09 09 6f 90 01 01 00 00 0a 09 6f 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 13 04 06 73 90 01 01 00 00 0a 13 05 00 11 05 11 04 16 73 90 01 01 00 00 0a 13 06 00 73 90 01 01 00 00 0a 13 07 00 11 06 11 07 6f 90 01 01 00 00 0a 00 11 07 6f 90 01 01 00 00 0a 0b 00 de 0d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}