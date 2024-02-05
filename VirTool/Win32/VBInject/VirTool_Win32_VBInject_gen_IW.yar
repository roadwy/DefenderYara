
rule VirTool_Win32_VBInject_gen_IW{
	meta:
		description = "VirTool:Win32/VBInject.gen!IW,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {ff c6 1c 1d 00 04 70 ff 6c 0c 00 } //01 00 
		$a_03_1 = {f5 f8 00 00 00 aa f5 28 00 00 00 6c 90 01 02 b2 aa 90 00 } //01 00 
		$a_03_2 = {f3 00 01 c1 e7 04 90 01 01 ff 9d fb 12 fc 0d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}