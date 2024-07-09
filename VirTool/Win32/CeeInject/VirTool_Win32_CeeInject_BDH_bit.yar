
rule VirTool_Win32_CeeInject_BDH_bit{
	meta:
		description = "VirTool:Win32/CeeInject.BDH!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {55 8b ec 51 89 45 fc 8b 5d fc [0-10] 81 c3 [0-10] ff d3 } //1
		$a_03_1 = {8d 45 f8 50 6a 40 68 ?? ?? ?? ?? 56 e8 ?? ?? ?? ff [0-10] 33 c0 89 45 fc } //1
		$a_03_2 = {ff 45 f8 43 90 0a f0 00 8a 03 [0-10] 34 ?? [0-10] 92 e8 ?? ?? ?? ff [0-10] 8b 4d fc [0-10] 83 c1 01 [0-10] 89 4d fc } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}