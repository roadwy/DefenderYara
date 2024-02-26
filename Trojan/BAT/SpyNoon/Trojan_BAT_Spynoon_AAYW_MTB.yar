
rule Trojan_BAT_Spynoon_AAYW_MTB{
	meta:
		description = "Trojan:BAT/Spynoon.AAYW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {11 0c 08 11 08 1f 16 5d 91 61 13 0d } //01 00 
		$a_01_1 = {11 0d 11 0b 59 13 0e 07 11 09 11 0e 20 00 01 00 00 5d d2 9c } //01 00 
		$a_01_2 = {07 11 0a 91 20 00 01 00 00 58 13 0b } //01 00 
		$a_01_3 = {50 6f 77 65 72 5f 54 72 6f 75 62 6c 65 73 68 6f 6f 74 65 72 2e 50 72 6f 70 65 72 74 69 65 73 } //00 00  Power_Troubleshooter.Properties
	condition:
		any of ($a_*)
 
}