
rule Trojan_BAT_MetaStealer_NB_MTB{
	meta:
		description = "Trojan:BAT/MetaStealer.NB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_01_0 = {25 06 93 0b 06 18 58 93 07 61 0b 17 13 0e 2b 80 } //00 00 
	condition:
		any of ($a_*)
 
}