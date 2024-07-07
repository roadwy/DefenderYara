
rule Trojan_BAT_AgentTesla_EPK_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.EPK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {4f 00 35 00 36 00 57 00 48 00 38 00 35 00 5a 00 37 00 36 00 48 00 35 00 48 00 47 00 35 00 46 00 38 00 34 00 37 00 38 00 48 00 35 00 } //1 O56WH85Z76H5HG5F8478H5
		$a_01_1 = {53 00 6b 00 65 00 74 00 63 00 68 00 } //1 Sketch
		$a_01_2 = {47 65 74 54 79 70 65 73 } //1 GetTypes
		$a_01_3 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggableAttribute
		$a_01_4 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } //1 DebuggingModes
		$a_01_5 = {47 65 74 4d 65 74 68 6f 64 } //1 GetMethod
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}