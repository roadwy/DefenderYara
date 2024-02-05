
rule Trojan_BAT_SnakeKeylogger_SPCP_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.SPCP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_81_0 = {44 6f 67 54 6f 57 69 6e } //01 00 
		$a_81_1 = {4b 72 75 73 6b 61 6c 5f 36 34 } //01 00 
		$a_81_2 = {44 65 6c 65 74 65 5f 41 72 63 6f 5f 36 34 } //01 00 
		$a_81_3 = {52 65 63 6f 72 72 69 64 6f 5f 50 72 6f 66 75 6e 69 64 61 64 5f 36 34 } //01 00 
		$a_81_4 = {61 44 61 79 41 74 54 68 65 52 61 63 65 73 } //00 00 
	condition:
		any of ($a_*)
 
}