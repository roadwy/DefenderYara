
rule Trojan_BAT_Razy_AMBH_MTB{
	meta:
		description = "Trojan:BAT/Razy.AMBH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {fe 0e 03 00 fe 90 01 02 00 00 01 58 00 59 6f 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 28 90 01 01 00 00 0a fe 0c 01 00 20 90 00 } //02 00 
		$a_03_1 = {fe 0c 01 00 fe 0c 02 00 93 fe 0e 03 00 fe 0c 00 00 fe 0c 03 00 fe 09 02 00 59 d1 6f 90 01 01 00 00 0a 26 fe 0c 02 00 20 90 01 01 00 00 00 20 90 01 04 65 65 65 65 65 65 65 65 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}