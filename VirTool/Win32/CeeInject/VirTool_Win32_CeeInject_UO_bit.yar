
rule VirTool_Win32_CeeInject_UO_bit{
	meta:
		description = "VirTool:Win32/CeeInject.UO!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {55 8b ec 8b 55 08 8b c2 c1 e0 04 8b ca 03 45 0c c1 e9 05 03 4d 10 33 c1 8b 4d 14 03 ca 33 c1 5d } //1
		$a_03_1 = {33 c8 2b d9 53 e8 90 01 04 33 c9 2b f8 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}