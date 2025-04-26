
rule VirTool_Win32_Obfuscator_AP{
	meta:
		description = "VirTool:Win32/Obfuscator.AP,SIGNATURE_TYPE_PEHSTR_EXT,05 00 03 00 05 00 00 "
		
	strings :
		$a_00_0 = {2e 72 61 77 64 61 74 } //1 .rawdat
		$a_00_1 = {78 6d 67 2e 65 78 65 } //1 xmg.exe
		$a_00_2 = {72 65 6c 64 65 6c 00 00 5c 64 72 69 76 65 72 73 5c 6e 74 66 73 2e 73 79 73 00 00 00 74 72 75 73 73 00 } //1
		$a_02_3 = {8d 86 38 01 00 00 66 81 00 29 37 8b 96 30 01 00 00 [0-20] 6a 05 } //2
		$a_02_4 = {40 00 ff e0 90 09 09 00 35 ?? ?? ?? ?? 8d 05 } //2
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_02_3  & 1)*2+(#a_02_4  & 1)*2) >=3
 
}