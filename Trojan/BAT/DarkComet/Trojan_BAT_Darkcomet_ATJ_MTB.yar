
rule Trojan_BAT_Darkcomet_ATJ_MTB{
	meta:
		description = "Trojan:BAT/Darkcomet.ATJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {0d 0a 2b 46 02 50 17 8d 2d 00 00 01 13 04 11 04 16 06 8c 1f 00 00 01 a2 11 04 14 28 } //00 00 
	condition:
		any of ($a_*)
 
}