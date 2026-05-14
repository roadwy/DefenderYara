
rule Trojan_Win32_AgentB_HVD_MTB{
	meta:
		description = "Trojan:Win32/AgentB.HVD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {04 ff d5 32 06 32 c3 88 06 8b 44 24 ?? 40 83 f8 1c } //2
		$a_03_1 = {8a 04 0e 8a d3 32 01 f6 d2 32 c2 88 01 ?? ?? 88 11 43 41 83 fb 1c } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}