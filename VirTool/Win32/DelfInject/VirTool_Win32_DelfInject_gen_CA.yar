
rule VirTool_Win32_DelfInject_gen_CA{
	meta:
		description = "VirTool:Win32/DelfInject.gen!CA,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {66 8b 0b 0f b7 d1 c1 ea 0c 66 81 e1 ff 0f 0f b7 c9 83 fa 03 75 0a 8b 55 f8 03 d1 8b 4d 10 01 0a 83 c3 02 48 75 da } //1
		$a_03_1 = {32 c2 88 45 ?? eb [0-05] 40 72 } //1
		$a_03_2 = {2b 4d 08 8b 55 0c 90 90 66 81 3a 4d 5a 90 90 75 ?? 90 (90 90 81 3a 50 45 00 00 90 90 75 ?? 8b 52 78 |)} //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=2
 
}