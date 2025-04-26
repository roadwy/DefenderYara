
rule VirTool_Win32_HackerHouse_A_MTB{
	meta:
		description = "VirTool:Win32/HackerHouse.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_03_0 = {10 6a 40 68 00 10 00 00 68 ?? ?? ?? ?? [0-02] 50 ff 15 ?? ?? ?? 10 8b f8 b9 ?? ?? ?? ?? be ?? ?? ?? 10 f3 a5 66 a5 a4 ff d0 } //2
		$a_03_1 = {55 8b ec 83 6d 0c 01 75 20 6a 00 6a 00 6a 00 68 ?? ?? ?? 10 6a 00 6a 00 ff 15 ?? ?? ?? 10 85 c0 74 07 50 ff 15 } //2
		$a_00_2 = {70 61 79 6c 6f 61 64 2e 64 6c 6c } //2 payload.dll
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_00_2  & 1)*2) >=6
 
}