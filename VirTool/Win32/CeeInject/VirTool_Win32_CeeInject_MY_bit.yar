
rule VirTool_Win32_CeeInject_MY_bit{
	meta:
		description = "VirTool:Win32/CeeInject.MY!bit,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_03_0 = {83 e9 01 51 8b 15 90 01 04 52 8b 45 90 01 01 50 6a 00 8b 4d 90 01 01 51 ff 55 90 00 } //1
		$a_03_1 = {eb 33 eb 01 c3 8b 45 90 01 01 89 85 90 01 04 8b 8d 90 01 04 03 8d 90 01 04 8b 95 90 01 04 03 95 90 01 04 8a 02 88 01 90 00 } //1
		$a_03_2 = {8b 08 33 0d 90 01 04 8b 15 90 01 04 89 0a 90 00 } //1
		$a_01_3 = {8b ff 8b c9 8b ff 50 8b ff 8b c9 8b ff c3 } //1
		$a_03_4 = {8b c9 8b c9 33 c9 8d 05 90 01 04 48 03 08 51 c3 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1+(#a_03_4  & 1)*1) >=4
 
}