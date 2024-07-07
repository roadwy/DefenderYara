
rule VirTool_Win32_Obfuscator_AOH{
	meta:
		description = "VirTool:Win32/Obfuscator.AOH,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {66 81 fd 00 fd 90 13 89 ec 5d 90 00 } //1
		$a_03_1 = {66 81 fd 00 fe 90 13 89 ec 5d 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule VirTool_Win32_Obfuscator_AOH_2{
	meta:
		description = "VirTool:Win32/Obfuscator.AOH,SIGNATURE_TYPE_PEHSTR_EXT,06 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b f9 79 0c dd 05 90 01 04 dd 05 90 01 04 d9 c1 d8 e1 d8 c1 d8 c1 d8 c1 d8 e1 d8 c1 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}