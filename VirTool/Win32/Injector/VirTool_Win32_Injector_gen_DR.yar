
rule VirTool_Win32_Injector_gen_DR{
	meta:
		description = "VirTool:Win32/Injector.gen!DR,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {03 7f 3c 6a 40 68 00 30 00 00 ff 77 50 ff 77 34 ff b5 ?? ?? ?? ?? e8 } //2
		$a_03_1 = {46 66 3b 77 06 72 ?? 8b 85 ?? ?? ?? ?? 03 47 28 } //1
		$a_03_2 = {ff ff 02 00 01 00 90 09 04 00 c7 85 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}