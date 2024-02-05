
rule Trojan_BAT_SnakeKeylogger_EH_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.EH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 06 00 00 0a 00 "
		
	strings :
		$a_81_0 = {24 65 30 36 66 32 62 34 36 2d 37 30 32 38 2d 34 35 38 37 2d 38 63 38 63 2d 61 34 63 65 39 37 38 33 62 63 62 38 } //01 00 
		$a_81_1 = {00 58 58 58 58 58 58 58 00 } //01 00 
		$a_81_2 = {4d 64 35 44 65 63 72 79 70 74 } //01 00 
		$a_81_3 = {47 61 6e 67 42 61 6e 67 } //01 00 
		$a_81_4 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //01 00 
		$a_81_5 = {41 63 74 69 76 61 74 6f 72 } //00 00 
	condition:
		any of ($a_*)
 
}