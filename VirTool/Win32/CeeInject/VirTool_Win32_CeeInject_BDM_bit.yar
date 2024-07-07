
rule VirTool_Win32_CeeInject_BDM_bit{
	meta:
		description = "VirTool:Win32/CeeInject.BDM!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b f0 54 6a 40 68 90 01 04 56 e8 90 01 03 ff 33 ff 90 02 10 33 db b2 2b 8b c3 03 c6 90 02 10 8a 8f 90 01 04 88 4c 24 04 90 02 10 32 54 24 04 88 10 90 02 10 8d 47 02 8b f8 43 81 fb 90 01 04 75 90 00 } //1
		$a_03_1 = {89 45 fc 8b 75 fc 68 90 01 04 01 34 24 c3 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}