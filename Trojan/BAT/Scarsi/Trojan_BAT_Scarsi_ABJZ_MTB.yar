
rule Trojan_BAT_Scarsi_ABJZ_MTB{
	meta:
		description = "Trojan:BAT/Scarsi.ABJZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {11 04 09 06 09 8e 69 5d 91 08 06 91 61 d2 6f 90 01 03 0a 06 17 58 0a 06 08 8e 69 32 e3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}