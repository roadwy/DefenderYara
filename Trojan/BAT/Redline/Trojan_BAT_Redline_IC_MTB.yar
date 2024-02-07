
rule Trojan_BAT_Redline_IC_MTB{
	meta:
		description = "Trojan:BAT/Redline.IC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 0a 00 "
		
	strings :
		$a_03_0 = {0b 07 14 72 90 01 04 72 90 01 04 72 90 01 04 28 90 01 03 0a 18 8d 90 01 04 14 14 14 17 7e 90 01 04 20 90 01 04 97 29 90 01 03 11 26 2a 90 00 } //01 00 
		$a_80_1 = {73 00 69 00 78 00 42 00 34 00 6c 00 30 00 } //s  01 00 
		$a_01_2 = {73 69 78 42 34 6c 30 } //00 00  sixB4l0
	condition:
		any of ($a_*)
 
}