
rule VirTool_Win32_Injector_gen_EM{
	meta:
		description = "VirTool:Win32/Injector.gen!EM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {53 56 85 c0 0f 84 8e 00 00 00 8b c8 8d 71 01 8a 19 41 84 db 75 f9 2b ce 83 c1 3a 81 f9 00 04 00 00 77 75 8d 95 fc fb ff ff 33 c9 8a 99 8c 66 01 10 88 9c 0d fc fb ff ff 41 84 db 75 ee 8b f0 8a 08 40 84 c9 75 f9 } //1
		$a_01_1 = {8b 45 fc 3b 45 0c 7d 2c 8b 4d 08 03 4d fc 0f b6 09 8b 45 fc 99 f7 7d 14 8b 45 10 0f be 14 10 33 ca 8b 45 08 03 45 fc 88 08 8b 4d fc 83 c1 01 89 4d fc eb cc 8b e5 5d } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}