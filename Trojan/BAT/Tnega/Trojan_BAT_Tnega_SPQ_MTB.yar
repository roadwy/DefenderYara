
rule Trojan_BAT_Tnega_SPQ_MTB{
	meta:
		description = "Trojan:BAT/Tnega.SPQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 03 00 "
		
	strings :
		$a_01_0 = {07 08 94 58 20 00 01 00 00 5d 94 13 0a 11 06 06 11 04 06 91 11 0a 61 d2 9c 06 17 } //02 00 
		$a_01_1 = {70 00 61 00 6c 00 61 00 63 00 65 00 77 00 70 00 6f 00 6c 00 73 00 63 00 65 00 2e 00 70 00 6c 00 2f 00 69 00 6d 00 61 00 67 00 65 00 73 00 2f 00 51 00 76 00 63 00 74 00 64 00 72 00 79 00 2e 00 6a 00 70 00 65 00 67 00 } //00 00 
	condition:
		any of ($a_*)
 
}