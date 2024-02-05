
rule Trojan_BAT_AveMaria_NEU_MTB{
	meta:
		description = "Trojan:BAT/AveMaria.NEU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {74 0f 00 00 01 6f 20 00 00 0a 74 11 00 00 01 0a 73 21 00 00 0a 0b 06 6f 22 00 00 0a 0c 20 00 10 00 00 8d 14 00 00 01 0d 38 0a 00 00 00 07 09 16 11 04 6f 23 00 00 0a 08 09 } //01 00 
		$a_01_1 = {41 00 72 00 64 00 61 00 6f 00 5f 00 52 00 61 00 70 00 63 00 66 00 7a 00 76 00 75 00 2e 00 6a 00 70 00 67 00 } //00 00 
	condition:
		any of ($a_*)
 
}