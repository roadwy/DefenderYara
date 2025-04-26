
rule Trojan_BAT_AgentTesla_EVS_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.EVS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {45 00 35 00 35 00 42 00 55 00 34 00 34 00 52 00 32 00 47 00 48 00 34 00 34 00 55 00 36 00 46 00 41 00 35 00 41 00 35 00 46 00 34 00 } //1 E55BU44R2GH44U6FA5A5F4
		$a_01_1 = {58 00 61 00 6d 00 61 00 72 00 69 00 6e 00 53 00 74 00 75 00 64 00 69 00 6f 00 } //1 XamarinStudio
		$a_01_2 = {43 6f 6e 73 74 72 75 63 74 69 6f 6e 43 61 6c 6c } //1 ConstructionCall
		$a_01_3 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggableAttribute
		$a_01_4 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } //1 DebuggingModes
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}