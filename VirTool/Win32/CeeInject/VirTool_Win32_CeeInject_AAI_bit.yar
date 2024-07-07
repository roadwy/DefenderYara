
rule VirTool_Win32_CeeInject_AAI_bit{
	meta:
		description = "VirTool:Win32/CeeInject.AAI!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {66 81 39 4d 5a 0f 85 90 01 04 8b 41 3c 68 00 01 00 00 03 c1 50 a3 90 01 04 ff d3 85 c0 75 71 a1 90 01 04 66 81 38 50 45 90 00 } //1
		$a_03_1 = {8b 75 0c 03 75 08 b0 08 22 e0 a1 90 01 04 03 f0 66 33 c0 8a 25 90 01 04 80 e2 19 0a d9 30 26 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}