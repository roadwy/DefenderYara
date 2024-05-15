
rule Trojan_BAT_zgRAT_NB_MTB{
	meta:
		description = "Trojan:BAT/zgRAT.NB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_01_0 = {11 27 11 20 61 19 11 1d 58 61 11 32 61 d2 9c } //00 00 
	condition:
		any of ($a_*)
 
}