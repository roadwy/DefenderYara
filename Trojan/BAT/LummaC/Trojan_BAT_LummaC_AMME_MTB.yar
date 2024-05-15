
rule Trojan_BAT_LummaC_AMME_MTB{
	meta:
		description = "Trojan:BAT/LummaC.AMME!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {03 11 11 8f 90 01 01 00 00 01 25 71 90 01 01 00 00 01 11 90 01 01 11 90 01 01 28 90 01 01 00 00 06 a5 90 01 01 00 00 01 61 d2 81 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}