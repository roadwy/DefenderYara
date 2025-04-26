
rule Trojan_BAT_AgentTesla_NSX_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NSX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {24 63 38 32 62 38 65 65 66 2d 64 63 37 34 2d 34 39 31 65 2d 62 63 61 31 2d 37 39 34 62 31 36 30 36 65 61 31 30 } //1 $c82b8eef-dc74-491e-bca1-794b1606ea10
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 43 68 61 72 41 72 72 61 79 } //1 FromBase64CharArray
		$a_01_2 = {4d 61 74 63 68 4e 75 6d 62 65 72 44 65 6c 65 67 61 74 65 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //1 MatchNumberDelegate.Resources.resources
		$a_01_3 = {47 65 74 54 79 70 65 46 72 6f 6d 48 61 6e 64 6c 65 } //1 GetTypeFromHandle
		$a_01_4 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerNonUserCodeAttribute
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}