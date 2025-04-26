
rule VirTool_Win32_Injector_gen_ED{
	meta:
		description = "VirTool:Win32/Injector.gen!ED,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {83 c4 08 b9 c9 03 00 00 be ?? ?? ?? ?? 8d bd 88 ec ff ff f3 a5 66 a5 a4 } //1
		$a_03_1 = {0f be 8c 05 88 ec ff ff 8b 55 f0 83 c2 01 83 f2 ?? 03 ca 88 4d ff } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}