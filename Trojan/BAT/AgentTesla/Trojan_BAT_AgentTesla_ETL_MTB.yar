
rule Trojan_BAT_AgentTesla_ETL_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ETL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {47 00 65 00 61 00 72 00 } //1 Gear
		$a_01_1 = {37 00 38 00 35 00 4a 00 48 00 47 00 34 00 35 00 34 00 35 00 37 00 53 00 43 00 41 00 37 00 41 00 53 00 35 00 42 00 34 00 39 00 37 00 } //1 785JHG45457SCA7AS5B497
		$a_01_2 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggableAttribute
		$a_01_3 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } //1 DebuggingModes
		$a_01_4 = {47 65 74 45 78 70 6f 72 74 65 64 54 79 70 65 73 } //1 GetExportedTypes
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}