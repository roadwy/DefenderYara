
rule Trojan_BAT_AgentTesla_KIJ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.KIJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggableAttribute
		$a_01_1 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 } //01 00  DebuggingMode
		$a_01_2 = {53 00 79 00 73 00 74 00 65 00 6d 00 2e 00 43 00 6f 00 6e 00 76 00 65 00 72 00 74 00 } //01 00  System.Convert
		$a_01_3 = {67 00 6e 00 69 00 72 00 74 00 53 00 34 00 36 00 65 00 73 00 61 00 42 00 6d 00 6f 00 72 00 46 00 } //01 00  gnirtS46esaBmorF
		$a_01_4 = {53 74 72 52 65 76 65 72 73 65 } //01 00  StrReverse
		$a_01_5 = {47 65 74 54 79 70 65 } //01 00  GetType
		$a_01_6 = {47 00 65 00 74 00 4d 00 65 00 74 00 68 00 6f 00 64 00 } //01 00  GetMethod
		$a_01_7 = {49 00 6e 00 76 00 6f 00 6b 00 65 00 } //00 00  Invoke
	condition:
		any of ($a_*)
 
}