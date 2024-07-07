
rule VirTool_Win32_Injector_gen_BQ{
	meta:
		description = "VirTool:Win32/Injector.gen!BQ,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {81 7e 08 2e 64 6c 6c 75 d8 81 3e 6b 65 72 6e 75 d0 80 7e 0c 00 75 ca 81 7e 04 65 6c 33 32 75 c1 } //1
		$a_01_1 = {ad 03 c3 ab e2 fa 8b 74 24 08 33 d2 4a 42 ad 03 c3 6a 00 50 e8 34 00 00 00 2b 44 24 28 75 ee d1 e2 03 54 24 0c 0f b7 02 d1 e0 d1 e0 03 44 24 04 8b 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}