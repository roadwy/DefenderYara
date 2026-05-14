
rule Trojan_Win64_AgentB_AHA_MTB{
	meta:
		description = "Trojan:Win64/AgentB.AHA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,32 00 32 00 02 00 00 "
		
	strings :
		$a_03_0 = {44 0f b6 42 fc 44 09 c0 44 0f b6 42 ff 41 c1 e0 ?? 44 09 c0 89 84 0c d0 00 00 00 48 83 c1 ?? 48 83 f9 ?? 75 } //30
		$a_03_1 = {41 89 ca 88 4a fc 88 6a fd 41 c1 ea ?? c1 e9 ?? 44 88 52 fe 88 4a ff 49 83 f9 ?? 75 } //20
	condition:
		((#a_03_0  & 1)*30+(#a_03_1  & 1)*20) >=50
 
}