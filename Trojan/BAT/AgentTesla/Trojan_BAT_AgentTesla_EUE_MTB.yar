
rule Trojan_BAT_AgentTesla_EUE_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.EUE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {00 5f 5f 5f 5f 5f 5f 5f 5f 5f 42 00 } //1 开彟彟彟彟B
		$a_01_1 = {00 5f 5f 5f 5f 5f 5f 5f 5f 5f 43 00 } //1 开彟彟彟彟C
		$a_01_2 = {00 5f 5f 5f 5f 5f 5f 5f 5f 5f 46 00 } //1 开彟彟彟彟F
		$a_01_3 = {00 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 4f 00 } //1 开彟彟彟彟彟彟彟彟彟O
		$a_01_4 = {86 06 45 00 86 06 45 00 86 06 45 00 86 06 45 00 86 06 } //1
		$a_01_5 = {42 00 75 00 6e 00 69 00 66 00 75 00 5f 00 54 00 65 00 78 00 74 00 42 00 6f 00 78 00 } //1 Bunifu_TextBox
		$a_01_6 = {47 65 74 45 78 70 6f 72 74 65 64 54 79 70 65 73 } //1 GetExportedTypes
		$a_01_7 = {47 65 74 4d 65 74 68 6f 64 } //1 GetMethod
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}