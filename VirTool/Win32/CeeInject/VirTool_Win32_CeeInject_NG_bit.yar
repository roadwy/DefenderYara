
rule VirTool_Win32_CeeInject_NG_bit{
	meta:
		description = "VirTool:Win32/CeeInject.NG!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {ff 75 fc ff 35 50 43 43 00 ff 75 e8 ff 75 f4 a1 c4 ab 43 00 a3 e4 ab 43 00 ff 15 e4 ab 43 00 } //1
		$a_01_1 = {eb 04 cd 37 cd 37 eb 04 cd 37 cd 37 eb 04 cd 37 cd 37 } //1
		$a_03_2 = {8b 45 f8 89 45 ?? 8b 4d ?? 03 4d ?? 8b 55 ?? 03 55 ?? 8a 02 88 01 8b 4d ?? 83 c1 01 89 4d ?? eb } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}