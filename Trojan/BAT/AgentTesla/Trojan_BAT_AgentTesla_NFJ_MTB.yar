
rule Trojan_BAT_AgentTesla_NFJ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NFJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {1f 1d 93 61 1f 7c 5f 9d 2a } //1
		$a_03_1 = {1f 64 91 03 5f 20 90 01 01 00 00 00 5f 9c 59 13 05 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule Trojan_BAT_AgentTesla_NFJ_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.NFJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {57 32 33 35 32 35 33 35 33 34 35 } //1 W2352535345
		$a_81_1 = {57 32 35 33 33 35 33 } //1 W253353
		$a_81_2 = {57 33 34 32 34 32 36 35 } //1 W3424265
		$a_81_3 = {47 65 74 50 69 78 65 6c } //1 GetPixel
		$a_81_4 = {54 6f 57 69 6e 33 32 } //1 ToWin32
		$a_81_5 = {43 6f 6c 6f 72 54 72 61 6e 73 6c 61 74 6f 72 } //1 ColorTranslator
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}