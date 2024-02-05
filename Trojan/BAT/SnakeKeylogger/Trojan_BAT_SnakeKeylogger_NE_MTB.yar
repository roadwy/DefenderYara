
rule Trojan_BAT_SnakeKeylogger_NE_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.NE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {12 07 28 54 00 00 0a 13 08 00 11 06 72 57 06 00 70 11 08 28 55 00 00 0a 13 06 00 12 07 28 56 00 00 0a 3a d9 ff ff ff } //01 00 
		$a_01_1 = {00 11 03 6f 35 00 00 0a 11 00 16 11 00 8e 69 28 29 00 00 06 13 04 } //00 00 
	condition:
		any of ($a_*)
 
}