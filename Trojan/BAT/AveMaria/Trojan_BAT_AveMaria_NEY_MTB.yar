
rule Trojan_BAT_AveMaria_NEY_MTB{
	meta:
		description = "Trojan:BAT/AveMaria.NEY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {6f 20 00 00 0a 06 20 e8 03 00 00 73 21 00 00 0a 0d 08 09 08 6f 22 00 00 0a 1e 5b 6f 23 00 00 0a 6f 24 00 00 0a 08 09 08 6f 25 00 00 0a 1e 5b } //01 00 
		$a_01_1 = {54 00 65 00 78 00 70 00 66 00 72 00 61 00 73 00 6c 00 70 00 70 00 65 00 6d 00 7a 00 62 00 69 00 62 00 79 00 6e 00 67 00 78 00 } //00 00 
	condition:
		any of ($a_*)
 
}