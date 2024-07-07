
rule VirTool_Win32_CeeInject_US_bit{
	meta:
		description = "VirTool:Win32/CeeInject.US!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {8b ca 89 45 90 01 01 31 4d 90 01 01 8b 45 90 02 20 01 05 90 02 10 8b ff 8b 0d 90 01 04 8b 15 90 01 04 89 11 90 00 } //1
		$a_03_1 = {8b 55 08 8b 02 03 45 90 01 01 8b 4d 08 89 01 90 00 } //1
		$a_03_2 = {0f b6 08 8d 94 11 90 01 04 8b 45 90 01 01 03 45 90 01 01 88 10 8b 4d 90 01 01 03 4d 90 01 01 0f b6 11 81 ea 90 01 04 8b 45 90 01 01 03 45 90 01 01 88 10 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}