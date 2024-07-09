
rule Worm_Win32_VB_AA_MTB{
	meta:
		description = "Worm:Win32/VB.AA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {53 48 45 4c 4c 33 32 2e 44 4c 4c } //1 SHELL32.DLL
		$a_00_1 = {53 68 65 6c 6c 45 78 65 63 75 74 65 41 } //1 ShellExecuteA
		$a_02_2 = {8b 45 08 ff 30 e8 ?? ?? ?? ?? 8b 4d 80 03 8d ?? ?? ff ff 8a 18 32 19 ff b5 ?? ?? ff ff 8b 45 08 ff 30 e8 ?? ?? ?? ?? 88 18 eb 02 eb ?? e9 ?? ?? ff ff } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_02_2  & 1)*1) >=3
 
}