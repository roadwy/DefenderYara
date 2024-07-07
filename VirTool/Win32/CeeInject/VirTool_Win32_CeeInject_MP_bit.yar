
rule VirTool_Win32_CeeInject_MP_bit{
	meta:
		description = "VirTool:Win32/CeeInject.MP!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {eb 2a 8b 45 90 01 01 89 85 90 01 04 8b 4d 90 01 01 03 8d 90 01 04 8b 55 90 01 01 03 95 90 01 04 8a 02 88 01 8b 4d 90 01 01 83 c1 01 89 4d 90 01 01 eb bc 90 00 } //1
		$a_03_1 = {c7 45 ec e1 14 00 00 8b 0d 90 01 04 3b 0d 90 01 04 72 02 eb 90 01 01 eb 00 90 00 } //1
		$a_03_2 = {8b c9 ff 35 90 01 04 8b c9 ff 35 90 01 04 33 d2 8d 05 90 01 04 48 48 03 10 8b c0 52 8b c0 c3 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}