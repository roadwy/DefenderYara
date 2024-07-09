
rule VirTool_Win32_Injector_gen_DH{
	meta:
		description = "VirTool:Win32/Injector.gen!DH,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_03_0 = {ff 73 18 ff 55 ?? 8b 1b 83 c3 24 8b 5b 04 0f b6 1b 81 cb 00 3a 5c 00 } //1
		$a_01_1 = {f3 a4 b0 e9 aa 8d 46 fc 2b c7 ab } //1
		$a_03_2 = {ff d0 03 45 ?? c7 00 5c 2a 2e 64 c7 40 04 6c 6c 00 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=2
 
}