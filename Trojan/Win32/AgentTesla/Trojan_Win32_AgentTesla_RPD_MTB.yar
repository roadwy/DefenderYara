
rule Trojan_Win32_AgentTesla_RPD_MTB{
	meta:
		description = "Trojan:Win32/AgentTesla.RPD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {88 10 8b 4d fc 03 4d e0 0f b6 11 81 ea ?? ?? ?? ?? 8b 45 fc 03 45 e0 88 10 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_AgentTesla_RPD_MTB_2{
	meta:
		description = "Trojan:Win32/AgentTesla.RPD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {81 c2 e0 d5 00 00 [0-15] b1 1e [0-15] 80 34 11 ?? e2 fa [0-15] 64 ff 35 24 00 00 00 [0-15] 8f 42 0a [0-15] b1 ff 52 e2 fd } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}