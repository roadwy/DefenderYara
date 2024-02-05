
rule VirTool_Win32_VBInject_gen_CZ{
	meta:
		description = "VirTool:Win32/VBInject.gen!CZ,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {6c 78 ff 6c 60 ff fc 90 fb 11 fc f0 6e ff 6c 78 ff f5 10 27 00 00 c2 f5 00 00 00 00 c7 1c bc 04 } //01 00 
		$a_01_1 = {f5 04 00 00 00 aa 71 6c ff f3 c3 00 2b 46 ff 6c 6c ff f5 01 00 00 00 0a 02 00 0c 00 3c 6c 6c ff } //00 00 
	condition:
		any of ($a_*)
 
}