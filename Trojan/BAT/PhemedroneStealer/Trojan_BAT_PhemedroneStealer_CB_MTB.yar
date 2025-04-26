
rule Trojan_BAT_PhemedroneStealer_CB_MTB{
	meta:
		description = "Trojan:BAT/PhemedroneStealer.CB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {fe 0c 00 00 fe 0c 02 00 91 fe 0e 03 00 7e ?? ?? ?? ?? fe 0c 02 00 7e ?? ?? ?? ?? 6f 6e 00 00 0a 5d 6f 1a 01 00 0a fe 0e 04 00 fe 0c 03 00 fe 0c 04 00 61 d1 fe 0e } //1
		$a_01_1 = {05 00 fe 0c 01 00 fe 0c 05 00 6f 93 01 00 0a 26 00 fe 0c 02 00 20 01 00 00 00 58 fe 0e 02 00 fe 0c 02 00 fe 0c 00 00 8e 69 fe 04 fe 0e 06 00 fe 0c 06 00 2d 94 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}