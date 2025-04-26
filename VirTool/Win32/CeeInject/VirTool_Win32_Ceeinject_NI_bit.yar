
rule VirTool_Win32_Ceeinject_NI_bit{
	meta:
		description = "VirTool:Win32/Ceeinject.NI!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {75 25 8b 55 ?? 8b 45 ?? 0f b7 0c 50 8b 55 ?? 8b 45 ?? 03 04 8a eb } //1
		$a_03_1 = {50 6a 00 6a 00 8b 4d ?? 51 6a 00 6a 00 8b 15 ?? ?? ?? ?? ff d2 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}