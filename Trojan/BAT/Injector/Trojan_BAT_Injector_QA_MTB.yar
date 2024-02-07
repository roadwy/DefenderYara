
rule Trojan_BAT_Injector_QA_MTB{
	meta:
		description = "Trojan:BAT/Injector.QA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {16 0a 2b 20 7e 90 01 0a 5d 91 10 01 02 06 02 06 91 03 61 28 90 01 04 9c 06 17 58 0a 06 02 8e 69 32 da 02 2a 90 00 } //01 00 
		$a_03_1 = {13 30 02 00 4b 00 00 00 01 00 00 11 28 90 01 12 0a 0a 28 90 01 17 04 8e 69 80 90 01 04 06 20 b0 00 00 00 28 90 01 0d 06 2a 90 00 } //00 00 
		$a_00_2 = {5d } //04 00  ]
	condition:
		any of ($a_*)
 
}