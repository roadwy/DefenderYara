
rule Trojan_BAT_AveMaria_NEC_MTB{
	meta:
		description = "Trojan:BAT/AveMaria.NEC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {02 25 17 58 10 00 91 1f 18 62 60 0c 28 31 00 00 0a 7e 01 00 00 04 02 08 6f 32 00 00 0a 28 33 00 00 0a } //01 00 
		$a_01_1 = {47 6f 6d 6f 6b 75 } //01 00 
		$a_01_2 = {54 61 73 6b 54 6f 2e 65 78 65 } //00 00 
	condition:
		any of ($a_*)
 
}