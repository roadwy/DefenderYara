
rule Trojan_BAT_Heracles_SPFP_MTB{
	meta:
		description = "Trojan:BAT/Heracles.SPFP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 01 00 00 03 00 "
		
	strings :
		$a_03_0 = {11 0b 11 09 16 73 90 01 03 0a 13 0c 11 0c 11 0a 6f 90 01 03 0a 11 0a 6f 90 01 03 0a 13 07 de 0f 16 2d 0b 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}