
rule Trojan_BAT_SnakeKeylogger_DAA_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.DAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 0c 00 00 0a 00 "
		
	strings :
		$a_01_0 = {57 b5 02 3c 09 07 00 00 00 00 00 00 00 00 00 00 01 00 00 00 65 00 00 00 4e 00 00 00 88 00 00 00 } //01 00 
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  FromBase64String
		$a_01_2 = {54 61 72 67 65 74 20 52 65 61 6c 74 79 } //01 00  Target Realty
		$a_01_3 = {47 65 74 44 6f 6d 61 69 6e } //01 00  GetDomain
		$a_01_4 = {47 5a 69 70 53 74 72 65 61 6d } //01 00  GZipStream
		$a_01_5 = {55 6e 77 72 61 70 } //0a 00  Unwrap
		$a_01_6 = {57 97 02 2a 09 0b 00 00 00 00 00 00 00 00 00 00 01 00 00 00 35 00 00 00 1e 00 00 00 27 00 00 00 } //01 00 
		$a_01_7 = {49 6e 66 69 6e 69 74 79 } //01 00  Infinity
		$a_01_8 = {47 65 74 45 78 74 65 6e 73 69 6f 6e } //01 00  GetExtension
		$a_01_9 = {47 65 74 54 65 6d 70 50 61 74 68 } //01 00  GetTempPath
		$a_01_10 = {67 65 74 5f 41 73 73 65 6d 62 6c 79 } //01 00  get_Assembly
		$a_01_11 = {52 6f 6c 6c 62 61 63 6b } //00 00  Rollback
	condition:
		any of ($a_*)
 
}