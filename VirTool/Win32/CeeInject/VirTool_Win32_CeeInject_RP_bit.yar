
rule VirTool_Win32_CeeInject_RP_bit{
	meta:
		description = "VirTool:Win32/CeeInject.RP!bit,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {8b f0 8d bd 90 01 03 ff b9 10 00 00 00 f3 a5 90 00 } //1
		$a_01_1 = {83 c4 08 8b f0 8d bd 04 ff ff ff b9 3e 00 00 00 f3 a5 } //1
		$a_03_2 = {6a 40 68 00 30 00 00 8b 85 90 01 03 ff 50 6a 00 e8 90 01 03 ff 89 45 fc 90 00 } //1
		$a_03_3 = {ff e0 6a 00 e8 90 01 03 ff 90 09 1e 00 8b 85 90 01 03 ff 2b 85 90 01 03 ff 3b 45 90 01 01 0f 82 90 01 03 ff 8b 45 fc 03 85 90 01 03 ff 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}