
rule Trojan_Win64_Tedy_SXC_MTB{
	meta:
		description = "Trojan:Win64/Tedy.SXC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_03_0 = {8d 50 ff 44 0f b6 44 08 ff 83 e2 ?? 44 32 04 3a 41 80 f0 ?? 44 88 44 04 ?? ?? ?? ?? ?? 74 1c 0f b6 14 08 41 89 c0 41 83 e0 ?? 41 32 14 38 80 f2 } //20
		$a_03_1 = {44 8d 40 ff 41 83 e0 ?? 44 0f b6 4c 08 ?? 44 0f b6 14 08 45 32 0c 38 41 80 f1 ?? 44 88 4c 10 ?? 41 89 c0 41 83 e0 ?? 45 32 14 38 41 80 f2 ?? 44 88 14 10 } //10
	condition:
		((#a_03_0  & 1)*20+(#a_03_1  & 1)*10) >=30
 
}