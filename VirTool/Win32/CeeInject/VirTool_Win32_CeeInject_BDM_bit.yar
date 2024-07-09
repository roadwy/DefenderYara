
rule VirTool_Win32_CeeInject_BDM_bit{
	meta:
		description = "VirTool:Win32/CeeInject.BDM!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b f0 54 6a 40 68 ?? ?? ?? ?? 56 e8 ?? ?? ?? ff 33 ff [0-10] 33 db b2 2b 8b c3 03 c6 [0-10] 8a 8f ?? ?? ?? ?? 88 4c 24 04 [0-10] 32 54 24 04 88 10 [0-10] 8d 47 02 8b f8 43 81 fb ?? ?? ?? ?? 75 } //1
		$a_03_1 = {89 45 fc 8b 75 fc 68 ?? ?? ?? ?? 01 34 24 c3 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}