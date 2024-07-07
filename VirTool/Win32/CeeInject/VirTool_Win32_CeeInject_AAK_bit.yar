
rule VirTool_Win32_CeeInject_AAK_bit{
	meta:
		description = "VirTool:Win32/CeeInject.AAK!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f b6 14 10 f7 da 8b 45 90 01 01 0f b6 0c 08 2b ca 8b 55 90 01 01 03 55 90 01 01 03 55 90 01 01 8b 45 90 01 01 88 0c 10 90 09 15 00 8b 4d 90 01 01 03 4d 90 01 01 03 4d 90 01 01 8b 55 90 01 01 03 55 90 01 01 03 55 90 01 01 8b 45 90 00 } //1
		$a_03_1 = {8b ff 8b ca a3 90 01 04 31 0d 90 01 04 a1 90 01 04 8b ff c7 05 90 01 04 00 00 00 00 8b ff 01 05 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}