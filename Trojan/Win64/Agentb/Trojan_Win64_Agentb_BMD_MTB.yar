
rule Trojan_Win64_Agentb_BMD_MTB{
	meta:
		description = "Trojan:Win64/Agentb.BMD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {44 89 c8 99 41 f7 fb 48 63 d2 8a 44 14 ?? 42 32 04 09 43 88 04 0a 49 ff c1 45 39 c8 7f } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}
rule Trojan_Win64_Agentb_BMD_MTB_2{
	meta:
		description = "Trojan:Win64/Agentb.BMD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {49 89 c1 41 83 e1 ?? 46 8a 4c 0c ?? 44 32 0c 01 44 88 0c 02 48 ff c0 41 39 c0 7f e4 } //2
		$a_03_1 = {ff c1 88 88 ?? ?? ?? ?? 0f b6 c9 44 8a 0c 08 45 01 cb 44 88 98 ?? ?? ?? ?? 45 0f b6 db 42 8a 1c 18 88 1c 08 46 88 0c 18 44 02 0c 08 45 0f b6 c9 42 8a 0c 08 42 30 0c 12 49 ff c2 45 39 d0 7f b3 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}