
rule Trojan_BAT_AgentTesla_NTH_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NTH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {24 39 37 35 62 61 37 34 33 2d 37 65 36 66 2d 34 35 36 39 2d 62 61 35 30 2d 37 34 37 64 34 32 30 30 63 33 39 32 } //01 00  $975ba743-7e6f-4569-ba50-747d4200c392
		$a_01_1 = {4c 61 62 6f 72 61 74 6f 69 72 65 5f 34 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //01 00  Laboratoire_4.Resources.resources
		$a_01_2 = {54 6f 53 74 72 69 6e 67 } //01 00  ToString
		$a_01_3 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggerNonUserCodeAttribute
		$a_01_4 = {47 65 74 45 78 70 6f 72 74 65 64 54 79 70 65 73 } //01 00  GetExportedTypes
		$a_01_5 = {47 65 74 4f 62 6a 65 63 74 56 61 6c 75 65 } //01 00  GetObjectValue
		$a_01_6 = {4c 61 74 65 47 65 74 } //01 00  LateGet
		$a_01_7 = {46 72 6f 6d 42 61 73 65 36 34 43 68 61 72 41 72 72 61 79 } //00 00  FromBase64CharArray
	condition:
		any of ($a_*)
 
}