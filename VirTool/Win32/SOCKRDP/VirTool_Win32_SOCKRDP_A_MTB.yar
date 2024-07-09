
rule VirTool_Win32_SOCKRDP_A_MTB{
	meta:
		description = "VirTool:Win32/SOCKRDP.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {89 45 fc 0f b6 05 b8 83 40 00 56 83 c8 01 c7 45 f4 00 00 00 00 50 68 5c 62 40 00 6a ff ff 15 ?? ?? ?? ?? a3 bc 83 40 00 85 c0 75 0a ff 15 ?? ?? ?? ?? 8b f0 } //1
		$a_03_1 = {33 c4 89 84 24 a4 48 00 00 56 8b 75 0c 57 33 ff c7 05 b4 83 40 00 ?? ?? ?? ?? 68 f8 61 40 00 89 7c 24 18 c6 05 b8 83 40 00 04 c7 05 b0 83 40 00 e4 61 40 00 e8 b2 ?? ?? ?? 8b 4d 08 83 c4 ?? 83 f9 ?? 7e 0f 8b d6 e8 ?? ?? ?? ?? 85 c0 0f 84 25 05 00 00 } //1
		$a_01_2 = {ff d6 6a 00 0f 57 c9 89 7c 24 34 6a 00 0f 11 4c 24 3c 6a 00 0f 28 44 24 3c 66 0f 73 d9 0c 6a 00 a3 ac 83 40 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}