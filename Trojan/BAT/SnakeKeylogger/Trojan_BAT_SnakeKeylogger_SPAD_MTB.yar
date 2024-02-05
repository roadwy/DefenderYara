
rule Trojan_BAT_SnakeKeylogger_SPAD_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.SPAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {06 20 c4 28 00 00 28 90 01 03 06 28 90 01 03 0a 20 ab 28 00 00 28 90 01 03 06 28 90 01 03 0a 6f 90 01 03 0a 0b 73 90 01 03 0a 0c 02 28 90 01 03 06 75 03 00 00 1b 73 90 01 03 0a 0d 09 07 16 73 0f 00 00 0a 13 04 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}