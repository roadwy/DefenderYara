
rule VirTool_Win32_CeeInject_BDT_bit{
	meta:
		description = "VirTool:Win32/CeeInject.BDT!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8d 45 f8 50 6a 40 68 ?? ?? ?? ?? 8b 45 fc 50 e8 ?? ?? ?? ff [0-10] 33 c0 89 06 [0-10] 33 c0 89 45 f8 } //1
		$a_03_1 = {ff 45 f8 43 81 7d f8 ?? ?? ?? ?? 75 b7 [0-10] 8b 4d fc [0-10] 81 c1 [0-10] ff d1 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}