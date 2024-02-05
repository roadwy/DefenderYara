
rule VirTool_Win32_VBInject_AGU{
	meta:
		description = "VirTool:Win32/VBInject.AGU,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {dd 05 f0 10 40 00 d9 e0 dd 1d 3c 10 43 00 df e0 a8 0d 0f 85 50 02 00 00 } //01 00 
		$a_03_1 = {c7 45 d4 03 00 00 00 8d 45 d4 50 dd 05 90 09 07 00 c7 45 dc 90 00 } //01 00 
		$a_03_2 = {99 6a 09 59 f7 f9 90 09 0f 00 c7 05 90 01 08 a1 90 00 } //03 00 
		$a_01_3 = {3d 29 f6 29 f6 75 } //00 00 
		$a_00_4 = {87 10 00 } //00 81 
	condition:
		any of ($a_*)
 
}