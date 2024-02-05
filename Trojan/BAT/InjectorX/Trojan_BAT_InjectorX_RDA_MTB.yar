
rule Trojan_BAT_InjectorX_RDA_MTB{
	meta:
		description = "Trojan:BAT/InjectorX.RDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {13 04 11 0a 75 0e 00 00 1b 11 0c 93 13 05 11 0a 75 0e 00 00 1b 11 0c 17 58 93 11 05 61 13 06 1f 0e 13 0e } //00 00 
	condition:
		any of ($a_*)
 
}