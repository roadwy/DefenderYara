
rule VirTool_Win32_Injector_KR_bit{
	meta:
		description = "VirTool:Win32/Injector.KR!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {51 89 45 fc ff 75 fc 81 04 24 1c 0d 00 00 } //01 00 
		$a_03_1 = {54 6a 40 68 e2 59 00 00 57 e8 90 01 03 ff 90 00 } //01 00 
		$a_03_2 = {8b f7 03 f2 90 02 20 8a 08 90 02 20 80 f1 79 90 02 20 88 0e 90 02 20 42 90 00 } //01 00 
		$a_03_3 = {81 3c 24 e3 59 00 00 75 90 02 20 8b c7 e8 90 01 03 ff 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}