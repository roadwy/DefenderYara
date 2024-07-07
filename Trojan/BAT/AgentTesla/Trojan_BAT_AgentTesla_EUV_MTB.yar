
rule Trojan_BAT_AgentTesla_EUV_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.EUV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {48 00 38 00 35 00 48 00 34 00 46 00 38 00 53 00 53 00 35 00 34 00 55 00 50 00 52 00 38 00 48 00 34 00 35 00 34 00 51 00 53 00 5a 00 } //1 H85H4F8SS54UPR8H454QSZ
		$a_01_1 = {43 00 6f 00 6e 00 76 00 65 00 72 00 74 00 65 00 72 00 } //1 Converter
		$a_01_2 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_01_3 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggableAttribute
		$a_01_4 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } //1 DebuggingModes
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}