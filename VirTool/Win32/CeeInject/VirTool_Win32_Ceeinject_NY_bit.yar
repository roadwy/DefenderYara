
rule VirTool_Win32_Ceeinject_NY_bit{
	meta:
		description = "VirTool:Win32/Ceeinject.NY!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 06 83 c6 90 01 01 2b 05 90 01 04 c1 c0 90 01 01 33 05 90 01 04 c1 0d 01 90 01 04 ab bb 90 01 04 3b f3 7c 90 00 } //1
		$a_03_1 = {8b c0 52 50 68 90 01 04 ff 35 90 01 04 ff 15 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}