
rule Trojan_BAT_AgentTesla_NYN_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NYN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {24 32 65 30 32 61 34 62 39 2d 32 63 30 36 2d 34 66 66 30 2d 62 66 63 62 2d 64 64 61 38 35 37 63 62 65 37 65 31 } //1 $2e02a4b9-2c06-4ff0-bfcb-dda857cbe7e1
		$a_01_1 = {47 65 74 4d 65 74 68 6f 64 } //1 GetMethod
		$a_01_2 = {52 65 70 6c 61 63 65 } //1 Replace
		$a_01_3 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggableAttribute
		$a_01_4 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerNonUserCodeAttribute
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule Trojan_BAT_AgentTesla_NYN_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.NYN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {08 09 16 20 00 10 00 00 6f 90 01 03 0a 0b 07 16 fe 02 13 06 11 06 2c 2e 06 90 00 } //1
		$a_01_1 = {17 02 1e 09 0f 00 00 00 fa 01 33 00 16 00 00 01 00 00 00 af 00 00 00 40 00 00 00 bd 00 00 00 55 01 00 00 20 01 00 00 12 00 00 00 6a 01 00 00 58 } //1
		$a_01_2 = {24 34 33 38 31 39 30 31 34 2d 62 61 33 62 2d 34 36 33 39 2d 38 32 63 66 2d 64 33 62 37 62 30 39 34 32 30 66 38 } //1 $43819014-ba3b-4639-82cf-d3b7b09420f8
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}