
rule VirTool_Win32_CeeInject_AAR_bit{
	meta:
		description = "VirTool:Win32/CeeInject.AAR!bit,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {8a 4c 24 14 03 c3 03 c5 8a 10 32 d1 43 81 fb da 04 00 00 88 10 } //1
		$a_03_1 = {03 c8 03 c3 90 09 0a 00 a1 ?? ?? ?? ?? b9 } //1
		$a_01_2 = {3d 4e e6 40 bb } //1
		$a_01_3 = {53 55 55 53 } //1 SUUS
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}