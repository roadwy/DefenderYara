
rule Trojan_Win32_PWSZbot_GNT_MTB{
	meta:
		description = "Trojan:Win32/PWSZbot.GNT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,16 00 16 00 04 00 00 "
		
	strings :
		$a_02_0 = {55 33 07 08 8b ?? ?? ?? ?? c1 c0 ?? ba ?? ?? ?? ?? c1 ca 15 03 c2 c1 c8 16 89 45 b8 e9 d3 01 00 00 } //10
		$a_02_1 = {8b f8 23 fa 3b fa 0f 85 ?? ?? ?? ?? c1 e1 ?? c1 e0 ?? eb ec 41 33 df } //10
		$a_01_2 = {68 4f 70 74 6e 52 65 65 } //1 hOptnRee
		$a_01_3 = {64 33 64 38 74 68 6b 2e 64 6c 6d } //1 d3d8thk.dlm
	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*10+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=22
 
}