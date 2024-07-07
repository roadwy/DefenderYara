
rule VirTool_Win32_CeeInject_BDX_bit{
	meta:
		description = "VirTool:Win32/CeeInject.BDX!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b c1 83 e0 03 8a 44 05 f8 30 44 0d fc 41 83 f9 04 72 ed 80 7d fc e9 75 10 80 7d fd 40 75 0a 38 5d fe 75 05 38 5d ff 74 03 } //1
		$a_03_1 = {8b c1 83 e0 03 8a 44 05 f8 30 81 90 01 04 41 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}