
rule VirTool_Win32_CeeInject_BDK_bit{
	meta:
		description = "VirTool:Win32/CeeInject.BDK!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {bb 01 00 00 00 90 05 10 01 90 8b c2 03 c3 90 05 10 01 90 c6 00 ?? 90 05 10 01 90 43 81 fb ?? ?? ?? ?? 75 } //1
		$a_03_1 = {8d 45 f8 50 6a 40 68 af 5b 00 00 56 e8 [0-10] 33 c0 89 45 fc [0-10] 33 c0 89 45 f8 bb [0-10] 8b c6 03 45 fc [0-10] 8b d0 8a 03 e8 ?? ?? ?? ff [0-10] 8b 55 fc [0-10] 83 c2 01 [0-10] [0-10] 89 55 fc [0-10] ff 45 f8 43 81 7d f8 ?? ?? ?? ?? 75 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}