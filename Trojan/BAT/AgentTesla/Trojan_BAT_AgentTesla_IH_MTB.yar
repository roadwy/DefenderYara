
rule Trojan_BAT_AgentTesla_IH_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.IH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 04 00 00 "
		
	strings :
		$a_02_0 = {04 03 02 7b ?? ?? ?? 04 91 02 7b ?? ?? ?? 04 61 d2 9c } //10
		$a_80_1 = {47 65 74 42 79 74 65 73 } //GetBytes  1
		$a_80_2 = {43 6c 61 73 73 4c 69 62 72 61 72 79 } //ClassLibrary  1
		$a_80_3 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //InvokeMember  1
	condition:
		((#a_02_0  & 1)*10+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=13
 
}