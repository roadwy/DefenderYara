
rule Trojan_BAT_AgentTesla_IW_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.IW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 0a 00 00 0a 00 "
		
	strings :
		$a_00_0 = {11 07 11 01 02 11 01 91 11 03 61 d2 9c } //0a 00 
		$a_02_1 = {0b 07 16 73 90 01 03 0a 0c 20 00 00 10 00 8d 90 01 03 01 0d 90 00 } //01 00 
		$a_81_2 = {43 6c 61 73 73 4c 69 62 72 61 72 79 } //01 00  ClassLibrary
		$a_81_3 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //01 00  CreateInstance
		$a_81_4 = {41 63 74 69 76 61 74 6f 72 } //01 00  Activator
		$a_81_5 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //01 00  InvokeMember
		$a_81_6 = {47 65 74 54 79 70 65 46 72 6f 6d 48 61 6e 64 6c 65 } //01 00  GetTypeFromHandle
		$a_81_7 = {47 65 74 4d 65 74 68 6f 64 } //01 00  GetMethod
		$a_81_8 = {47 65 74 45 78 65 63 75 74 69 6e 67 41 73 73 65 6d 62 6c 79 } //01 00  GetExecutingAssembly
		$a_81_9 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //00 00  DebuggerNonUserCodeAttribute
	condition:
		any of ($a_*)
 
}