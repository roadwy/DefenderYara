
rule Trojan_BAT_AgentTesla_EQC_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.EQC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {33 00 56 00 35 00 32 00 48 00 54 00 42 00 34 00 48 00 35 00 51 00 35 00 4e 00 46 00 42 00 34 00 39 00 47 00 35 00 38 00 43 00 35 00 } //1 3V52HTB4H5Q5NFB49G58C5
		$a_01_1 = {53 00 70 00 65 00 63 00 74 00 72 00 61 00 32 00 } //1 Spectra2
		$a_01_2 = {47 65 74 54 79 70 65 } //1 GetType
		$a_01_3 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggableAttribute
		$a_01_4 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } //1 DebuggingModes
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}