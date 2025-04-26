
rule VirTool_Win32_Ninject_G{
	meta:
		description = "VirTool:Win32/Ninject.G,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {01 d0 8a 10 8b 85 ?? ?? ?? ?? 30 94 ?? ?? ?? ?? ?? eb } //1
		$a_03_1 = {8a 00 32 02 88 c2 8b 85 ?? ?? ?? ?? 03 85 ?? ?? ?? ?? 88 10 e9 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}