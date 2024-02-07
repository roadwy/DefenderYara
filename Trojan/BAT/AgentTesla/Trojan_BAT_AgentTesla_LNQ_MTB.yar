
rule Trojan_BAT_AgentTesla_LNQ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.LNQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {54 56 71 51 41 41 4d 41 41 41 41 45 41 41 41 41 2f 2f } //01 00  TVqQAAMAAAAEAAAA//
		$a_01_1 = {2f 2f 38 41 41 4c 67 41 41 41 41 41 41 41 41 41 51 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 } //01 00  //8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAA
		$a_81_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  FromBase64String
		$a_01_3 = {47 65 74 53 74 72 69 6e 67 } //01 00  GetString
		$a_01_4 = {52 65 70 6c 61 63 65 } //01 00  Replace
		$a_01_5 = {49 6e 76 6f 6b 65 } //01 00  Invoke
		$a_01_6 = {47 65 74 54 79 70 65 73 } //01 00  GetTypes
		$a_01_7 = {47 65 74 4d 65 74 68 6f 64 } //00 00  GetMethod
	condition:
		any of ($a_*)
 
}