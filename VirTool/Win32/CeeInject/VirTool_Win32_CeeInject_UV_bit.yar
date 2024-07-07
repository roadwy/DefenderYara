
rule VirTool_Win32_CeeInject_UV_bit{
	meta:
		description = "VirTool:Win32/CeeInject.UV!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 50 ff 75 90 01 01 ff 75 90 01 01 ff 35 90 01 04 59 ff d1 90 00 } //1
		$a_03_1 = {c6 01 00 8b 55 90 01 01 03 55 90 01 01 0f b6 02 8b 4d 90 01 01 03 4d 90 01 01 0f b6 11 8d 84 02 90 01 04 8b 4d 90 01 01 03 4d 90 01 01 88 01 8b 55 90 01 01 03 55 90 01 01 0f b6 02 2d 90 01 04 8b 4d 90 01 01 03 4d 90 01 01 88 01 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}