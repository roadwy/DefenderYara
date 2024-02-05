
rule Trojan_BAT_SnakeKeylogger_DB_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.DB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 01 00 "
		
	strings :
		$a_81_0 = {2f 2f 74 65 73 74 2e 63 6f 2f 74 73 74 } //01 00 
		$a_81_1 = {57 65 62 48 65 61 64 65 72 43 6f 6c 6c 65 63 74 69 6f 6e } //01 00 
		$a_81_2 = {4e 61 6d 65 56 61 6c 75 65 43 6f 6c 6c 65 63 74 69 6f 6e } //01 00 
		$a_81_3 = {4d 79 20 54 65 73 74 20 48 65 61 64 65 72 20 56 61 6c 75 65 } //01 00 
		$a_81_4 = {46 6f 72 67 6f 74 4d 6f 64 65 6c } //01 00 
		$a_81_5 = {47 5a 69 70 53 74 72 65 61 6d } //01 00 
		$a_81_6 = {68 65 6c 6c 6f } //01 00 
		$a_81_7 = {77 6f 72 6c 64 } //01 00 
		$a_81_8 = {44 69 73 63 6f 72 64 } //00 00 
	condition:
		any of ($a_*)
 
}