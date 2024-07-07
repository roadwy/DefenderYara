
rule Trojan_BAT_SnakeKeylogger_SPRU_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.SPRU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {0c 16 13 04 2b 17 00 08 11 04 07 11 04 9a 1f 10 28 8c 00 00 0a 9c 00 11 04 17 58 13 04 11 04 07 8e 69 fe 04 13 05 11 05 2d dc } //4
		$a_01_1 = {77 61 6c 6c 73 53 6c 69 70 70 65 64 54 68 72 6f 75 67 68 } //1 wallsSlippedThrough
		$a_01_2 = {72 65 73 65 74 57 6f 6e 43 61 72 64 73 44 65 63 6b 6b } //1 resetWonCardsDeckk
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=6
 
}