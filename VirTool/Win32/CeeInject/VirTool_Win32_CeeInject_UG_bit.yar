
rule VirTool_Win32_CeeInject_UG_bit{
	meta:
		description = "VirTool:Win32/CeeInject.UG!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {52 33 ed 55 a3 90 01 04 89 0d 90 01 04 ff d0 90 00 } //1
		$a_03_1 = {8d 9b 00 00 00 00 8b 15 90 01 04 8a 8c 02 90 01 04 8b 15 90 01 04 88 0c 02 40 3b 05 90 01 04 72 e1 90 00 } //1
		$a_01_2 = {8b cf c1 e9 05 03 4b 0c 8b d7 c1 e2 04 03 53 08 50 33 ca 8d 14 38 33 ca 2b f1 8b ce c1 e9 05 03 4b 04 8b d6 c1 e2 04 03 13 33 ca 8d 14 30 33 ca 2b f9 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}