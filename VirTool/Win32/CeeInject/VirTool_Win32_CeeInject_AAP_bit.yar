
rule VirTool_Win32_CeeInject_AAP_bit{
	meta:
		description = "VirTool:Win32/CeeInject.AAP!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {5a 2b 55 14 89 45 14 03 d0 ff e2 90 09 07 00 b9 ?? ?? ?? ?? f3 a4 } //1
		$a_01_1 = {3b f1 72 17 87 06 33 45 20 03 45 24 87 06 83 ee 04 eb ed } //1
		$a_01_2 = {66 81 3e 4d 5a } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}