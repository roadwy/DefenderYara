
rule Trojan_BAT_Injuke_FAS_MTB{
	meta:
		description = "Trojan:BAT/Injuke.FAS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {61 d1 9d fe 90 01 01 01 00 20 1e 5b 86 0a 65 20 13 dc f0 11 61 66 20 0f 87 76 1b 61 59 25 fe 90 01 01 01 00 20 57 d0 24 27 20 a8 2f db d8 58 66 65 3c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}