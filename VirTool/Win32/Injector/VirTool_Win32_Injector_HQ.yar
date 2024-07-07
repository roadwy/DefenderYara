
rule VirTool_Win32_Injector_HQ{
	meta:
		description = "VirTool:Win32/Injector.HQ,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {ff d0 5a 89 45 fc 33 c0 8a 03 43 85 c0 75 f9 53 8b 42 10 50 8b 42 08 ff d0 89 } //1
		$a_01_1 = {8b 4d 04 8b 7d fc 57 51 8b 75 f8 03 f1 4e c1 e9 03 8b d1 b3 66 56 51 b9 08 00 00 00 8a 07 32 c3 88 06 47 } //1
		$a_01_2 = {eb 06 8a 06 88 07 47 46 8b 45 f0 3b f0 72 c7 } //1
		$a_01_3 = {74 16 48 8b f0 51 57 fc f3 a4 5f 59 03 f9 42 42 42 42 43 43 43 43 eb df } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}