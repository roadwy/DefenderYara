
rule VirTool_Win32_CeeInject_LW{
	meta:
		description = "VirTool:Win32/CeeInject.LW,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 02 33 85 ?? ?? ff ff 8b 4d ?? 89 01 8b e5 5d c3 } //1
		$a_01_1 = {55 8b ec 8b 45 08 8b 08 03 4d 0c 8b 55 08 89 0a 5d c3 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}