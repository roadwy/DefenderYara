
rule Trojan_BAT_AgentTesla_NOK_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NOK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {24 36 65 66 38 66 31 30 37 2d 63 34 64 32 2d 34 62 34 64 2d 61 37 33 32 2d 33 32 63 32 30 37 33 32 33 37 34 61 } //01 00  $6ef8f107-c4d2-4b4d-a732-32c20732374a
		$a_01_1 = {5f 5a 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f } //01 00  _Z_________________________________________
		$a_01_2 = {49 44 65 66 65 72 72 65 64 } //01 00  IDeferred
		$a_01_3 = {00 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 00 } //01 00  䄀䅁䅁䅁䅁䅁䅁䅁䅁䅁䅁A
		$a_01_4 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  FromBase64String
		$a_01_5 = {52 65 70 6c 61 63 65 } //01 00  Replace
		$a_01_6 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggableAttribute
		$a_01_7 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //00 00  DebuggerNonUserCodeAttribute
	condition:
		any of ($a_*)
 
}