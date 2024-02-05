
rule Trojan_BAT_Bingoml_ACS_MTB{
	meta:
		description = "Trojan:BAT/Bingoml.ACS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {0a 0b 00 09 17 58 0d 09 20 00 01 00 00 fe 04 13 04 11 04 } //00 00 
	condition:
		any of ($a_*)
 
}