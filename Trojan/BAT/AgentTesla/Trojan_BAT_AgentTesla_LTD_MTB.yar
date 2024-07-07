
rule Trojan_BAT_AgentTesla_LTD_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.LTD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {50 72 6f 67 72 66 66 66 66 66 66 66 66 66 66 61 6d } //1 Progrffffffffffam
		$a_01_1 = {23 67 73 64 67 67 67 67 67 67 67 23 } //1 #gsdggggggg#
		$a_01_2 = {61 66 73 66 61 23 6b 6a 64 23 } //1 afsfa#kjd#
		$a_01_3 = {23 66 61 73 66 73 61 66 2e 64 6c 6c 23 } //1 #fasfsaf.dll#
		$a_01_4 = {23 66 61 73 67 61 67 2e 64 6c 6c 23 } //1 #fasgag.dll#
		$a_01_5 = {23 67 64 66 73 66 64 73 2e 64 6c 6c 23 } //1 #gdfsfds.dll#
		$a_01_6 = {46 72 6f 6d 42 61 73 65 36 34 } //1 FromBase64
		$a_01_7 = {47 65 74 4d 65 74 68 6f 64 } //1 GetMethod
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}