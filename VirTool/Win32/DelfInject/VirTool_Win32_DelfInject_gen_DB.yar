
rule VirTool_Win32_DelfInject_gen_DB{
	meta:
		description = "VirTool:Win32/DelfInject.gen!DB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {2b 42 34 03 45 ?? 2d 00 10 00 00 05 00 02 00 00 89 45 ?? 6a 00 6a 01 6a 00 ff 55 90 1b 01 [0-20] 8b 45 ?? 8b 40 1c 8b 55 ?? 2b 42 34 03 45 ?? 2d 00 10 00 00 05 00 02 00 00 89 45 ?? [0-20] 6a 00 6a 01 6a 00 ff 55 90 1b 01 } //1
		$a_03_1 = {8b 80 c0 00 00 00 03 45 ?? 2d 00 10 00 00 05 00 02 00 00 89 45 ?? 8b 45 ?? 8b 55 ec 2b 50 34 81 ea 00 10 00 00 81 c2 00 02 00 00 89 55 fc 8b 45 ?? 8b 40 18 03 45 fc 89 45 ?? 6a 00 6a 01 6a 00 ff 55 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}