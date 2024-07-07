
rule VirTool_Win32_Injector_IH_bit{
	meta:
		description = "VirTool:Win32/Injector.IH!bit,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_03_0 = {68 00 30 00 00 68 00 10 00 00 e9 90 01 02 ff ff 90 00 } //1
		$a_03_1 = {88 10 8b 45 f8 83 c0 01 89 45 f8 8b 4d 08 e9 90 01 02 00 00 90 00 } //1
		$a_03_2 = {03 45 f0 8b 4d f4 03 4d f8 8a 11 e9 90 01 02 ff ff 90 00 } //1
		$a_03_3 = {33 94 8d 00 fc ff ff e9 90 01 02 ff ff 90 00 } //1
		$a_01_4 = {8b 55 08 8b 82 c4 03 00 00 ff d0 } //1
		$a_03_5 = {8b 45 08 8b 88 94 03 00 00 e9 90 01 02 ff ff 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1+(#a_01_4  & 1)*1+(#a_03_5  & 1)*1) >=6
 
}