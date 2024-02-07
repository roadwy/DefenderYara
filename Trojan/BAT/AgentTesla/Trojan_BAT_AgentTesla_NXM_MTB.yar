
rule Trojan_BAT_AgentTesla_NXM_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NXM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {24 65 33 35 34 37 63 35 39 2d 34 37 65 66 2d 34 33 37 64 2d 38 62 66 31 2d 35 64 38 30 31 34 36 65 63 65 31 66 } //01 00  $e3547c59-47ef-437d-8bf1-5d80146ece1f
		$a_01_1 = {4b 59 4f 49 4b 55 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //01 00  KYOIKU.Resources.resources
		$a_01_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  FromBase64String
		$a_01_3 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggableAttribute
		$a_01_4 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //00 00  DebuggerNonUserCodeAttribute
	condition:
		any of ($a_*)
 
}