
rule Trojan_BAT_Tnega_PA_MTB{
	meta:
		description = "Trojan:BAT/Tnega.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 38 00 30 00 2e 00 36 00 36 00 2e 00 37 00 35 00 2e 00 32 00 35 00 2f 00 } //01 00  http://80.66.75.25/
		$a_01_1 = {19 2d 09 26 2b 21 0a 2b ea 0b 2b f3 0c 2b f5 07 08 18 5b 02 08 18 6f 26 00 00 0a 1f 10 28 27 00 00 0a 9c 08 } //00 00 
	condition:
		any of ($a_*)
 
}