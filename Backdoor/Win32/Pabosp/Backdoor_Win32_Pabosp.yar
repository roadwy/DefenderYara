
rule Backdoor_Win32_Pabosp{
	meta:
		description = "Backdoor:Win32/Pabosp,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 04 00 00 "
		
	strings :
		$a_03_0 = {8d 4c 24 08 51 ff 15 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 84 c0 74 ?? 6a 05 68 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 54 24 04 8b 44 24 00 89 42 04 b0 01 } //5
		$a_00_1 = {61 76 67 73 70 2e 65 78 65 } //2 avgsp.exe
		$a_00_2 = {4d 61 6b 65 41 6e 64 53 68 6f 77 45 67 67 } //2 MakeAndShowEgg
		$a_00_3 = {44 65 6c 65 74 65 4d 79 73 65 6c 66 } //2 DeleteMyself
	condition:
		((#a_03_0  & 1)*5+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2+(#a_00_3  & 1)*2) >=9
 
}