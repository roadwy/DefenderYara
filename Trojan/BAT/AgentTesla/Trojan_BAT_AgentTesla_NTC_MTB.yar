
rule Trojan_BAT_AgentTesla_NTC_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NTC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {24 35 34 37 30 33 33 34 33 2d 61 64 66 30 2d 34 39 34 32 2d 39 64 35 61 2d 31 37 62 31 36 64 34 39 30 30 35 31 } //1 $54703343-adf0-4942-9d5a-17b16d490051
		$a_01_1 = {50 72 6f 6a 65 63 74 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //1 Project.Properties.Resources.resources
		$a_01_2 = {47 65 74 4d 65 74 68 6f 64 73 } //1 GetMethods
		$a_01_3 = {47 65 74 54 79 70 65 73 } //1 GetTypes
		$a_01_4 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggableAttribute
		$a_01_5 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerNonUserCodeAttribute
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}