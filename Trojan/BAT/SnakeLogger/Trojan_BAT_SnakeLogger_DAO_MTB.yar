
rule Trojan_BAT_SnakeLogger_DAO_MTB{
	meta:
		description = "Trojan:BAT/SnakeLogger.DAO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 02 00 "
		
	strings :
		$a_03_0 = {0c 16 13 05 2b 16 08 11 05 07 11 05 9a 1f 10 28 90 01 01 00 00 0a d2 9c 11 05 17 58 13 05 11 05 07 8e 69 fe 04 13 06 11 06 2d dd 90 00 } //01 00 
		$a_01_1 = {44 6f 6f 64 6c 65 4a 75 6d 70 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //01 00 
		$a_01_2 = {52 65 70 6c 61 63 65 } //01 00 
		$a_01_3 = {53 70 6c 69 74 } //00 00 
	condition:
		any of ($a_*)
 
}