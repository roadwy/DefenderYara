
rule Trojan_BAT_Heracles_SPFF_MTB{
	meta:
		description = "Trojan:BAT/Heracles.SPFF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 04 00 "
		
	strings :
		$a_01_0 = {08 09 58 0c 09 17 58 0d 09 02 31 f4 } //00 00 
	condition:
		any of ($a_*)
 
}