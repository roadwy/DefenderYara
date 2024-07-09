
rule VirTool_Win32_CeeInject_AAW_bit{
	meta:
		description = "VirTool:Win32/CeeInject.AAW!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {c6 07 6b c6 47 ?? 65 c6 47 ?? 72 c6 47 ?? 6e c6 47 ?? 65 c6 47 ?? 6c c6 47 ?? 33 } //1
		$a_03_1 = {8b 3a 83 ea ?? 4a f7 d7 83 ef ?? 4f 01 cf 83 ef 01 31 c9 01 f9 57 8f 46 00 83 c6 05 4e 83 c3 ?? 4b 8d 3d ?? ?? ?? ?? 81 c7 ?? ?? ?? ?? ff e7 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}