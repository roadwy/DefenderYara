
rule HackTool_Win64_Inject_SXB_MTB{
	meta:
		description = "HackTool:Win64/Inject.SXB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,2e 00 2e 00 04 00 00 "
		
	strings :
		$a_03_0 = {48 89 44 24 28 e8 ?? ?? ?? ?? 84 c0 74 ?? 48 8b 15 ?? ?? ?? ?? 4c 8d 44 24 20 48 8b 0d 59 20 06 00 41 b9 06 00 00 00 c7 44 24 20 b8 01 00 00 66 c7 44 24 24 c0 c3 e8 } //30
		$a_03_1 = {48 8d 44 24 30 41 b9 06 00 00 00 4c 8d 05 ?? ?? ?? ?? 48 89 44 24 20 ff 15 ?? ?? ?? ?? 85 c0 0f 95 c0 48 8b 4c 24 38 48 33 cc } //5
		$a_80_2 = {53 79 73 4d 61 69 6e } //SysMain  10
		$a_80_3 = {6e 74 64 6c 6c 2e 64 6c 6c } //ntdll.dll  1
	condition:
		((#a_03_0  & 1)*30+(#a_03_1  & 1)*5+(#a_80_2  & 1)*10+(#a_80_3  & 1)*1) >=46
 
}