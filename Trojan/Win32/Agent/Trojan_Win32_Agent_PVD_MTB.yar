
rule Trojan_Win32_Agent_PVD_MTB{
	meta:
		description = "Trojan:Win32/Agent.PVD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_02_0 = {8b 74 24 1c 8b c1 83 44 24 1c 04 2b c3 2d 2f 16 00 00 0f b7 d8 8b 44 24 18 05 ?? ?? ?? ?? 83 6c 24 20 01 89 06 } //2
		$a_02_1 = {53 38 00 00 ba ?? ?? ?? ?? eb ?? 81 f2 ec f1 33 11 } //2
		$a_02_2 = {57 81 e9 3a 66 0d 77 01 ce 90 09 0c 00 32 81 ?? ?? ?? ?? 20 81 } //2
	condition:
		((#a_02_0  & 1)*2+(#a_02_1  & 1)*2+(#a_02_2  & 1)*2) >=2
 
}