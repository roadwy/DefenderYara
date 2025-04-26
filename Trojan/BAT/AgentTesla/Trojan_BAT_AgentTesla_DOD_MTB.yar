
rule Trojan_BAT_AgentTesla_DOD_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.DOD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {24 37 32 37 63 65 66 37 62 2d 37 35 33 62 2d 34 35 65 61 2d 62 61 65 36 2d 34 39 32 30 66 39 65 39 35 34 64 33 } //1 $727cef7b-753b-45ea-bae6-4920f9e954d3
		$a_01_1 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggableAttribute
		$a_01_2 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } //1 DebuggingModes
		$a_01_3 = {47 65 74 54 79 70 65 46 72 6f 6d 48 61 6e 64 6c 65 } //1 GetTypeFromHandle
		$a_01_4 = {54 6f 49 6e 74 33 32 } //1 ToInt32
		$a_01_5 = {41 73 73 65 6d 62 6c 79 43 6f 70 79 72 69 67 68 74 } //1 AssemblyCopyright
		$a_01_6 = {41 73 73 65 6d 62 6c 79 54 72 61 64 65 6d 61 72 6b } //1 AssemblyTrademark
		$a_01_7 = {41 73 73 65 6d 62 6c 79 43 6f 6d 70 61 6e 79 } //1 AssemblyCompany
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}