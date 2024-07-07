
rule VirTool_Win32_CeeInject_gen_CM{
	meta:
		description = "VirTool:Win32/CeeInject.gen!CM,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {80 7c 37 01 46 75 90 01 01 80 7c 37 02 75 75 90 01 01 80 7c 37 03 4a 75 90 01 01 80 7c 37 04 30 75 90 01 01 80 7c 37 05 78 75 90 01 01 80 7c 37 06 41 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}