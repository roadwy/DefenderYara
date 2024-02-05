
rule Trojan_BAT_Bladabindi_DB_MTB{
	meta:
		description = "Trojan:BAT/Bladabindi.DB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {07 72 41 00 00 70 28 01 00 00 06 0c 08 6f 1c 00 00 0a 14 17 8d 01 00 00 01 13 04 11 04 16 02 a2 11 04 6f 1d 00 00 0a 26 de 0a } //01 00 
		$a_01_1 = {0d 1b 8d 16 00 00 01 13 05 11 05 16 09 6f 1e 00 00 0a 6f 1f 00 00 0a a2 11 05 17 28 20 00 00 0a a2 11 05 18 09 6f 21 00 00 0a a2 11 05 19 28 20 00 00 0a a2 11 05 1a 09 6f 22 00 00 0a a2 11 05 28 23 00 00 0a 28 24 00 00 0a 26 de 00 } //00 00 
	condition:
		any of ($a_*)
 
}