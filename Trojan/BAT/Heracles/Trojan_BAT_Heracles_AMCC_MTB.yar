
rule Trojan_BAT_Heracles_AMCC_MTB{
	meta:
		description = "Trojan:BAT/Heracles.AMCC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {11 05 1f 16 5d 91 13 0b 07 11 09 91 } //00 00 
	condition:
		any of ($a_*)
 
}