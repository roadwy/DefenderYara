
rule Trojan_BAT_Seraph_NSA_MTB{
	meta:
		description = "Trojan:BAT/Seraph.NSA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 05 00 "
		
	strings :
		$a_03_0 = {28 48 01 00 0a 6f 90 01 03 0a 20 90 01 03 00 fe 90 01 02 00 38 90 01 03 ff 11 0a 11 0a 6f 90 01 03 0a 11 0a 28 90 01 03 06 6f 90 01 03 0a 13 06 20 90 01 03 00 38 90 01 03 ff 00 11 02 11 06 17 73 90 01 03 0a 13 03 20 90 01 03 00 7e 90 01 03 04 7b 90 01 03 04 90 00 } //01 00 
		$a_01_1 = {59 7a 70 79 73 7a 72 62 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //01 00  Yzpyszrb.Properties.Resources.resources
		$a_01_2 = {70 70 62 75 72 61 74 70 } //00 00  ppburatp
	condition:
		any of ($a_*)
 
}