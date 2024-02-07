
rule Trojan_BAT_AgentTesla_NIM_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NIM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {23 66 61 61 78 76 64 61 73 64 73 66 66 67 73 73 61 73 66 64 73 66 64 64 66 73 66 67 64 66 66 6b 6b 6c 76 63 6c 6a 69 67 66 64 64 64 64 64 64 64 73 73 61 66 2e 64 6c 6c 23 } //01 00  #faaxvdasdsffgssasfdsfddfsfgdffkklvcljigfdddddddssaf.dll#
		$a_01_1 = {23 73 64 61 64 61 78 76 78 63 73 66 64 73 73 23 } //01 00  #sdadaxvxcsfdss#
		$a_01_2 = {23 61 66 61 64 78 76 61 64 64 61 64 66 73 73 66 66 61 73 73 66 67 76 78 63 64 64 66 67 64 66 66 73 73 67 73 66 2e 64 6c 6c 23 } //01 00  #afadxvaddadfssffassfgvxcddfgdffssgsf.dll#
		$a_01_3 = {23 69 6a 66 61 6b 64 73 78 61 64 64 6b 67 64 66 67 67 66 66 73 66 64 73 66 76 78 64 73 66 73 67 6b 2e 64 6c 6c 23 } //01 00  #ijfakdsxaddkgdfggffsfdsfvxdsfsgk.dll#
		$a_01_4 = {46 72 6f 6d 42 61 73 65 36 34 } //01 00  FromBase64
		$a_01_5 = {47 65 74 4d 65 74 68 6f 64 } //00 00  GetMethod
	condition:
		any of ($a_*)
 
}