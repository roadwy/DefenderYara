
rule Trojan_BAT_Heracles_GFM_MTB{
	meta:
		description = "Trojan:BAT/Heracles.GFM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {62 69 6e 47 42 72 69 64 67 65 38 75 73 62 31 } //01 00  binGBridge8usb1
		$a_01_1 = {45 53 5a 4f 6a 6b 49 6e 61 74 74 } //01 00  ESZOjkInatt
		$a_01_2 = {73 75 61 72 72 64 6f 36 64 61 37 56 64 65 72 } //01 00  suarrdo6da7Vder
		$a_01_3 = {76 73 73 38 72 65 6e 73 78 6f 6e } //01 00  vss8rensxon
		$a_01_4 = {4f 49 52 6d 4f 52 75 6e 74 63 66 67 } //00 00  OIRmORuntcfg
	condition:
		any of ($a_*)
 
}