
rule VirTool_Win32_DelfInject_DR_bit{
	meta:
		description = "VirTool:Win32/DelfInject.DR!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 03 89 06 ?? a1 ?? ?? 48 00 03 06 8a 00 ?? ?? 34 ?? 8b ?? ?? ?? 48 00 03 16 88 02 ?? ff 03 81 ?? ?? ?? ?? ?? 75 } //1
		$a_03_1 = {03 03 89 06 8b 06 89 03 ff ?? ?? ?? 48 00 5a ?? ff e2 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}