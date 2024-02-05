
rule Trojan_BAT_SnakeKeyLogger_RDB_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeyLogger.RDB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {31 34 33 38 66 33 61 35 2d 65 34 61 31 2d 34 37 35 65 2d 61 37 65 30 2d 65 38 32 31 66 37 37 33 34 33 64 65 } //01 00 
		$a_01_1 = {45 6e 65 72 47 6f 76 } //01 00 
		$a_01_2 = {53 74 72 69 6e 67 31 } //01 00 
		$a_01_3 = {43 00 6c 00 61 00 69 00 6d 00 73 00 49 00 64 00 } //00 00 
	condition:
		any of ($a_*)
 
}