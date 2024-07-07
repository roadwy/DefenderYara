
rule VirTool_Win32_CeeInject_CV{
	meta:
		description = "VirTool:Win32/CeeInject.CV,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {8a d0 c0 ea 02 8a cd c0 e1 04 80 e2 0f 32 d1 } //1
		$a_03_1 = {ff 75 1c ff 75 18 ff 75 14 ff 75 10 ff 75 0c ff 75 08 ff 15 90 01 04 8b f0 90 00 } //1
		$a_01_2 = {d5 53 ff d6 6a 02 6a 64 8d 4c 24 18 51 89 44 24 1c ff d7 85 c0 74 e3 5d } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}