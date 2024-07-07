
rule VirTool_Win32_CeeInject_gen_IO{
	meta:
		description = "VirTool:Win32/CeeInject.gen!IO,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 05 00 00 "
		
	strings :
		$a_01_0 = {64 8b 1d 30 00 00 00 8b 5b 0c 8b 5b 14 8b 1b 8b 1b 8b 5b 10 } //10
		$a_03_1 = {03 d6 52 50 51 ff 95 90 01 02 ff ff 8b 85 90 01 02 ff ff 0f b7 53 06 ff 0d 90 01 04 83 85 90 01 02 ff ff 28 90 00 } //1
		$a_03_2 = {52 6a 00 6a 00 6a 04 6a 00 6a 00 6a 00 6a 00 8b 45 08 50 ff 95 90 01 02 ff ff 85 c0 0f 84 90 00 } //1
		$a_03_3 = {50 57 57 6a 04 57 57 57 57 ff b5 90 01 01 ff ff ff ff 95 90 01 01 ff ff ff 85 c0 90 00 } //1
		$a_03_4 = {c7 00 07 00 01 00 8b 95 90 01 02 ff ff 50 52 90 02 0a ff 95 90 01 02 ff ff 90 00 } //1
	condition:
		((#a_01_0  & 1)*10+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1+(#a_03_4  & 1)*1) >=11
 
}