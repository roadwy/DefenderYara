
rule VirTool_Win32_Injector_gen_BW{
	meta:
		description = "VirTool:Win32/Injector.gen!BW,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {42 85 d2 7c 90 01 01 42 90 02 10 30 08 40 4a 75 90 01 01 c3 90 00 } //1
		$a_03_1 = {4b 85 db 75 90 01 01 bb 90 01 04 a1 90 01 04 50 b8 90 1b 02 e8 90 01 04 50 ff d3 33 c0 5a 59 59 64 89 10 68 90 01 04 8d 45 cc ba 09 00 00 00 e8 90 01 04 c3 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}