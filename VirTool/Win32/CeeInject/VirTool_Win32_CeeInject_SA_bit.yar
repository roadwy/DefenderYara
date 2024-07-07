
rule VirTool_Win32_CeeInject_SA_bit{
	meta:
		description = "VirTool:Win32/CeeInject.SA!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {8b ca 33 c1 8b d2 c7 45 fc 00 00 00 00 8b d2 01 45 fc } //1
		$a_03_1 = {ff 75 fc b8 90 01 04 48 50 ff 75 90 01 01 ff 75 90 01 01 a1 90 01 04 ff d0 90 00 } //1
		$a_03_2 = {1b c9 f7 d9 90 09 1d 00 8b 15 90 01 04 81 ea 90 01 04 89 15 90 01 04 a1 90 01 04 39 05 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}