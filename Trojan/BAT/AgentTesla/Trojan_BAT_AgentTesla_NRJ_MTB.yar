
rule Trojan_BAT_AgentTesla_NRJ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NRJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {24 65 37 65 62 61 33 33 32 2d 37 34 35 65 2d 34 31 33 39 2d 39 39 35 66 2d 63 61 31 35 36 36 36 65 63 31 61 33 } //1 $e7eba332-745e-4139-995f-ca15666ec1a3
		$a_01_1 = {44 61 69 6c 79 4e 6f 74 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //1 DailyNotes.Resources.resources
		$a_80_2 = {53 79 73 74 65 6d 2e 43 6f 6e 76 65 72 74 } //System.Convert  1
		$a_80_3 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //FromBase64String  1
		$a_80_4 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //InvokeMember  1
		$a_01_5 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerNonUserCodeAttribute
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}