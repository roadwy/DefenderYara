
rule VirTool_Win32_Ninject_E{
	meta:
		description = "VirTool:Win32/Ninject.E,SIGNATURE_TYPE_PEHSTR_EXT,02 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {31 c1 88 cb 8b 90 01 06 8b 90 01 06 88 1c 01 8b 90 01 06 83 c0 01 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}