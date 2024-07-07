
rule VirTool_Win32_Injector_gen_AG{
	meta:
		description = "VirTool:Win32/Injector.gen!AG,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {80 80 34 10 40 00 4e f2 0f c1 ca b9 e9 08 ab c2 c1 e1 21 08 c2 69 c8 43 fa d5 44 b9 f9 d8 3b 12 b9 31 30 33 2a f2 41 ff c1 c1 e1 d9 40 3d 00 66 00 00 72 cc } //1
		$a_01_1 = {80 80 34 76 40 00 fb 84 e7 d1 e1 4a c7 c1 19 78 5b b2 64 8d 0d 21 60 a3 da 0f c1 ca 69 c8 29 48 eb 02 40 3d 5f 03 00 00 72 d6 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}