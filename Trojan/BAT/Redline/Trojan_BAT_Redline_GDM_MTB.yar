
rule Trojan_BAT_Redline_GDM_MTB{
	meta:
		description = "Trojan:BAT/Redline.GDM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 0a 00 "
		
	strings :
		$a_03_0 = {26 2b 28 2b 29 2b 2e 2b 2f 2b 30 2b 35 0d 09 13 04 de 63 28 90 01 03 0a 2b e1 0b 2b e4 28 90 01 03 0a 2b c2 6f 90 01 03 0a 2b d2 07 2b d5 28 90 01 03 0a 2b d0 0c 2b cf 08 2b ce 28 90 01 03 2b 2b c9 90 00 } //01 00 
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //00 00 
	condition:
		any of ($a_*)
 
}