
rule Trojan_BAT_AgentTesla_NXT_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NXT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {24 65 37 30 63 31 33 30 36 2d 64 31 32 65 2d 34 64 33 65 2d 39 62 36 36 2d 66 63 62 64 34 37 63 61 35 61 66 36 } //1 $e70c1306-d12e-4d3e-9b66-fcbd47ca5af6
		$a_01_1 = {5d a2 df 09 1f 00 00 00 fa 25 33 00 16 00 00 02 } //1
		$a_01_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_3 = {52 65 70 6c 61 63 65 } //1 Replace
		$a_01_4 = {47 65 74 4f 62 6a 65 63 74 56 61 6c 75 65 } //1 GetObjectValue
		$a_01_5 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerNonUserCodeAttribute
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}