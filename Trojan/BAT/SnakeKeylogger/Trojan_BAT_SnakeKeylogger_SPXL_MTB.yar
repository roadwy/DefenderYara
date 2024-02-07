
rule Trojan_BAT_SnakeKeylogger_SPXL_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.SPXL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {11 05 09 5d 13 09 11 05 09 5b 13 0a 08 11 09 11 0a 6f 90 01 03 0a 13 0b 07 11 06 12 0b 28 90 01 03 0a 9c 11 06 17 58 13 06 11 05 17 58 13 05 11 05 09 11 04 5a 32 c9 90 00 } //01 00 
		$a_01_1 = {50 00 75 00 6e 00 74 00 6f 00 73 00 5f 00 64 00 65 00 5f 00 6c 00 61 00 5f 00 70 00 69 00 65 00 7a 00 61 00 } //00 00  Puntos_de_la_pieza
	condition:
		any of ($a_*)
 
}