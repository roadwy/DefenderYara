
rule VirTool_Win32_Ceeinject_NI_bit{
	meta:
		description = "VirTool:Win32/Ceeinject.NI!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {75 25 8b 55 90 01 01 8b 45 90 01 01 0f b7 0c 50 8b 55 90 01 01 8b 45 90 01 01 03 04 8a eb 90 00 } //1
		$a_03_1 = {50 6a 00 6a 00 8b 4d 90 01 01 51 6a 00 6a 00 8b 15 90 01 04 ff d2 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}