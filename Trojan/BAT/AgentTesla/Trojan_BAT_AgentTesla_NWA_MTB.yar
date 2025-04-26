
rule Trojan_BAT_AgentTesla_NWA_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NWA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {24 66 33 34 36 65 35 35 66 2d 34 36 64 33 2d 34 33 61 38 2d 39 31 65 39 2d 35 30 66 38 37 65 30 63 64 35 63 62 } //1 $f346e55f-46d3-43a8-91e9-50f87e0cd5cb
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 } //1 FromBase64
		$a_01_2 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_01_3 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggableAttribute
		$a_01_4 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerNonUserCodeAttribute
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}