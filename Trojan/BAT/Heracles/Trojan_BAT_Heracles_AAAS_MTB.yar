
rule Trojan_BAT_Heracles_AAAS_MTB{
	meta:
		description = "Trojan:BAT/Heracles.AAAS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {11 07 11 03 11 07 11 06 11 03 59 17 59 91 9c } //02 00 
		$a_01_1 = {11 07 11 06 11 03 59 17 59 11 04 9c } //00 00 
	condition:
		any of ($a_*)
 
}