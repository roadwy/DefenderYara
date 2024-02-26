
rule Trojan_BAT_SnakeKeylogger_SPXY_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.SPXY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 04 00 "
		
	strings :
		$a_03_0 = {06 0b 72 3f 0c 00 70 0c 08 72 8f 0c 00 70 72 67 0a 00 70 6f 90 01 03 0a 0d 07 28 90 01 03 0a 13 04 20 00 01 00 00 13 05 17 8d 12 00 00 01 25 16 7e 5c 00 00 04 a2 13 06 72 93 0c 00 70 72 60 0e 00 70 72 67 0a 00 70 28 90 01 03 0a 28 90 01 03 0a 13 07 11 07 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}