
rule VirTool_Win32_CeeInject_PH_bit{
	meta:
		description = "VirTool:Win32/CeeInject.PH!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {b8 67 66 66 66 f7 6c 24 90 01 01 d1 fa 8b c2 c1 e8 1f 03 c2 8b d8 0f af 90 01 01 24 90 01 01 0f af 5d 10 8a c3 32 44 24 90 00 } //2
		$a_03_1 = {8b 4d 10 85 c9 8b 45 08 74 0d 8a 54 24 90 01 01 8b 74 24 90 01 01 88 14 06 90 00 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1) >=3
 
}
rule VirTool_Win32_CeeInject_PH_bit_2{
	meta:
		description = "VirTool:Win32/CeeInject.PH!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 4d fc 3b 4d 0c 7d 1a 8b 55 08 03 55 fc 0f be 1a e8 90 01 04 33 d8 8b 45 08 03 45 fc 88 18 eb 90 00 } //1
		$a_03_1 = {55 8b ec a1 90 01 04 69 c0 90 01 04 05 90 01 04 a3 90 01 04 a1 90 01 04 c1 e8 90 01 01 25 90 01 04 5d c3 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}