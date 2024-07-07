
rule Trojan_BAT_AgentTesla_NON_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NON!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {5f 5a 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f } //1 _Z_________________________________________
		$a_01_1 = {24 66 65 63 38 65 66 62 33 2d 64 38 39 64 2d 34 31 30 34 2d 62 39 66 30 2d 30 61 65 62 62 66 33 34 31 38 38 61 } //1 $fec8efb3-d89d-4104-b9f0-0aebbf34188a
		$a_01_2 = {41 75 74 6f 4a 61 63 6b 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 } //1 AutoJack.Properties.Resources.resource
		$a_01_3 = {49 44 65 66 65 72 72 65 64 } //1 IDeferred
		$a_01_4 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_5 = {52 65 70 6c 61 63 65 } //1 Replace
		$a_01_6 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggableAttribute
		$a_01_7 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerNonUserCodeAttribute
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}