
rule VirTool_Win32_CeeInject_OM_bit{
	meta:
		description = "VirTool:Win32/CeeInject.OM!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {74 26 0f b7 05 90 01 04 05 90 01 04 8b 0d 90 01 04 03 4d 90 01 01 0f be 11 33 d0 a1 90 01 04 03 45 90 01 01 88 10 eb 90 00 } //1
		$a_03_1 = {33 45 f4 35 90 01 04 0f b7 0d 90 01 04 33 4d f4 81 f1 90 01 04 8b 15 90 01 04 8a 80 90 01 04 88 04 0a eb 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}