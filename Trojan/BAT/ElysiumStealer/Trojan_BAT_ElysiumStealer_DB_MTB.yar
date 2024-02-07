
rule Trojan_BAT_ElysiumStealer_DB_MTB{
	meta:
		description = "Trojan:BAT/ElysiumStealer.DB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,24 00 24 00 09 00 00 14 00 "
		
	strings :
		$a_81_0 = {67 73 64 66 67 73 64 } //0a 00  gsdfgsd
		$a_81_1 = {73 64 66 73 64 66 73 64 66 73 64 66 73 64 66 73 64 } //0a 00  sdfsdfsdfsdfsdfsd
		$a_81_2 = {68 64 66 68 64 66 67 64 66 } //01 00  hdfhdfgdf
		$a_81_3 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //01 00  IsDebuggerPresent
		$a_81_4 = {54 6f 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  ToBase64String
		$a_81_5 = {49 73 4c 6f 67 67 69 6e 67 } //01 00  IsLogging
		$a_81_6 = {74 65 73 74 65 72 } //01 00  tester
		$a_81_7 = {44 65 63 6f 6d 70 72 65 73 73 } //01 00  Decompress
		$a_81_8 = {44 65 63 72 79 70 74 } //00 00  Decrypt
	condition:
		any of ($a_*)
 
}