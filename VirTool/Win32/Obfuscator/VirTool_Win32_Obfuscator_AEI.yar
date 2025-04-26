
rule VirTool_Win32_Obfuscator_AEI{
	meta:
		description = "VirTool:Win32/Obfuscator.AEI,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0c 00 02 00 00 "
		
	strings :
		$a_01_0 = {0f b6 10 0f b6 01 03 d0 81 e2 ff 00 00 00 8a 4c 14 14 30 0c 3e 46 3b f5 72 c5 } //10
		$a_03_1 = {8a 54 24 0f 0f b6 c3 8a 88 ?? ?? ?? ?? 02 0e 02 d1 0f b6 c2 8d 44 04 14 8b ce 88 54 24 0f e8 ?? ?? ?? ?? fe c3 80 fb ?? 75 } //2
	condition:
		((#a_01_0  & 1)*10+(#a_03_1  & 1)*2) >=12
 
}