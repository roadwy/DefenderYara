
rule Trojan_BAT_Bladabindi_NBD_MTB{
	meta:
		description = "Trojan:BAT/Bladabindi.NBD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {fe 0c 01 00 fe 0c 00 00 28 90 01 01 00 00 0a 72 90 01 01 00 00 70 6f 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 6f 90 01 01 00 00 0a fe 90 01 02 00 20 90 01 01 00 00 00 6f 90 01 01 00 00 0a fe 90 01 02 00 20 90 01 01 00 00 00 6f 90 01 01 00 00 0a fe 90 01 02 00 6f 90 01 01 00 00 0a fe 90 01 02 00 fe 90 01 02 00 28 90 01 01 00 00 0a fe 90 01 02 00 fe 90 01 02 00 fe 90 01 02 00 20 90 01 01 00 00 00 fe 90 01 02 00 8e 69 6f 90 01 01 00 00 0a fe 90 01 02 00 28 90 01 01 00 00 0a fe 90 01 02 00 6f 90 01 01 00 00 0a 90 00 } //01 00 
		$a_01_1 = {74 6d 70 43 33 39 34 2e 74 6d 70 } //00 00  tmpC394.tmp
	condition:
		any of ($a_*)
 
}