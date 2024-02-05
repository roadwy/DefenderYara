
rule Trojan_BAT_Perseus_DHE_MTB{
	meta:
		description = "Trojan:BAT/Perseus.DHE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_02_0 = {11 05 11 04 6f 90 01 04 0d 90 01 01 09 28 90 01 05 da 28 90 01 04 28 90 01 04 28 90 01 05 11 04 17 d6 13 04 11 04 11 06 90 00 } //01 00 
		$a_01_1 = {45 00 6e 00 74 00 72 00 79 00 50 00 6f 00 69 00 6e 00 74 00 } //01 00 
		$a_01_2 = {49 00 6e 00 76 00 6f 00 6b 00 65 00 } //00 00 
	condition:
		any of ($a_*)
 
}