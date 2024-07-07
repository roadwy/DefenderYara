
rule VirTool_Win32_CeeInject_BCG_bit{
	meta:
		description = "VirTool:Win32/CeeInject.BCG!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {55 8b ec ff 75 0c 90 02 10 8a 45 08 90 02 10 59 90 02 10 30 01 90 02 10 5d c2 08 00 90 00 } //1
		$a_03_1 = {56 6a 40 52 53 6a ff e8 90 01 03 ff 90 02 10 33 c0 89 06 90 02 10 8b 06 03 c3 73 05 e8 90 01 03 ff 50 68 90 01 04 ff 15 90 02 10 ff 06 81 3e 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}