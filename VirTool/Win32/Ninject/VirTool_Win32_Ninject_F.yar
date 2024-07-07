
rule VirTool_Win32_Ninject_F{
	meta:
		description = "VirTool:Win32/Ninject.F,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {30 04 11 ff 45 fc 8b 45 fc 3b 45 14 } //1
		$a_03_1 = {32 04 0a 8b 90 01 05 8b 90 01 05 88 04 0a c7 85 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}