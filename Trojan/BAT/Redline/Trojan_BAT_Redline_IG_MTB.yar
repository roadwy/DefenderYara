
rule Trojan_BAT_Redline_IG_MTB{
	meta:
		description = "Trojan:BAT/Redline.IG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 0a 00 "
		
	strings :
		$a_03_0 = {0c 16 13 04 2b 21 00 07 11 04 08 11 04 08 6f 90 01 03 0a 5d 6f 90 01 03 0a 07 11 04 91 61 d2 9c 00 11 04 17 58 13 04 11 04 07 8e 69 fe 04 13 05 11 05 2d d2 90 00 } //01 00 
		$a_80_1 = {5b 4b 55 5d 5b 52 57 41 5d } //[KU][RWA]  01 00 
		$a_01_2 = {49 6e 76 6f 6b 65 } //00 00  Invoke
	condition:
		any of ($a_*)
 
}