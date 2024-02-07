
rule Trojan_BAT_SnakeKeylogger_DM_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.DM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 06 00 00 0a 00 "
		
	strings :
		$a_03_0 = {0a 03 08 03 6f 90 01 03 0a 5d 17 d6 28 90 01 03 0a 28 90 01 03 0a da 0d 06 09 b6 28 90 01 03 0a 28 90 01 03 0a 0a 08 17 d6 0c 00 08 07 fe 02 16 fe 01 13 04 11 04 2d bc 90 00 } //01 00 
		$a_81_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  FromBase64String
		$a_81_2 = {47 5a 69 70 53 74 72 65 61 6d } //01 00  GZipStream
		$a_81_3 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //01 00  CreateInstance
		$a_81_4 = {41 63 74 69 76 61 74 6f 72 } //01 00  Activator
		$a_81_5 = {53 75 6e 44 61 79 } //00 00  SunDay
	condition:
		any of ($a_*)
 
}