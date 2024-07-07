
rule Trojan_BAT_SystemBC_psyA_MTB{
	meta:
		description = "Trojan:BAT/SystemBC.psyA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 01 00 00 "
		
	strings :
		$a_01_0 = {07 9a 06 28 82 00 00 0a 39 0b 00 00 00 7e ad 04 00 04 74 71 00 00 01 2a 07 17 58 0b 07 7e ac 04 00 04 8e } //7
	condition:
		((#a_01_0  & 1)*7) >=7
 
}
rule Trojan_BAT_SystemBC_psyA_MTB_2{
	meta:
		description = "Trojan:BAT/SystemBC.psyA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 01 00 00 "
		
	strings :
		$a_01_0 = {72 5b 00 00 70 28 08 00 00 0a 19 6f 09 00 00 0a 28 17 00 00 0a 8c 14 00 00 01 28 18 00 00 0a 28 03 00 00 06 25 28 19 00 00 0a 28 1a 00 00 0a 72 b7 00 00 70 6f 1b 00 00 0a 72 c7 00 00 70 20 00 01 00 00 14 14 17 8d 01 00 00 01 25 16 02 a2 6f 1c 00 00 0a 26 de 07 } //7
	condition:
		((#a_01_0  & 1)*7) >=7
 
}