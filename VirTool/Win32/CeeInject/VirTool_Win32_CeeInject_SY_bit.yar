
rule VirTool_Win32_CeeInject_SY_bit{
	meta:
		description = "VirTool:Win32/CeeInject.SY!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {8b 45 08 33 d2 b9 1d f3 01 00 f7 f1 8b c8 b8 a7 41 00 00 f7 e2 8b d1 8b c8 b8 14 0b 00 00 f7 e2 2b c8 33 d2 8b c1 8b d9 f7 75 0c } //1
		$a_03_1 = {b8 4d 5a 00 00 66 39 01 75 f3 8b 41 3c 03 c1 81 38 50 45 00 00 75 e6 b9 90 01 04 66 39 48 18 75 db 90 00 } //1
		$a_03_2 = {ff 75 18 8b 35 90 01 04 8b ce ff 75 14 33 35 90 01 04 83 e1 1f ff 75 10 d3 ce ff 75 0c ff 75 08 85 f6 75 be 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}