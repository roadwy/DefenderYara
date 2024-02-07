
rule Trojan_BAT_Redline_GMG_MTB{
	meta:
		description = "Trojan:BAT/Redline.GMG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 0a 00 "
		
	strings :
		$a_03_0 = {03 08 03 8e 69 5d 91 07 08 07 8e 69 5d 91 61 28 90 01 03 06 03 08 1b 58 1b 59 17 58 03 8e 69 5d 91 59 20 90 01 04 58 1c 58 20 90 01 04 5d d2 9c 08 90 00 } //01 00 
		$a_01_1 = {61 48 52 30 63 44 70 6b 62 33 52 75 5a 58 52 77 5a 58 4a 73 63 79 31 6a 62 32 30 3d } //00 00  aHR0cDpkb3RuZXRwZXJscy1jb20=
	condition:
		any of ($a_*)
 
}