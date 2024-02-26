
rule Trojan_BAT_Redline_ARD_MTB{
	meta:
		description = "Trojan:BAT/Redline.ARD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {73 14 00 00 06 0b 1b 8d d1 00 00 01 0c 16 0d 2b 0e 09 06 08 09 1b 09 59 6f 47 00 00 0a 58 0d 09 1b 32 ee } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_Redline_ARD_MTB_2{
	meta:
		description = "Trojan:BAT/Redline.ARD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {11 00 11 02 91 11 00 11 03 91 58 20 00 01 00 00 5d 13 07 20 03 00 00 00 7e 90 01 01 01 00 04 7b 90 00 } //01 00 
		$a_03_1 = {11 00 11 02 11 00 11 03 91 9c 20 01 00 00 00 7e 90 01 01 01 00 04 7b 90 01 01 00 00 04 39 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}