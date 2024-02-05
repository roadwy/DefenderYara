
rule VirTool_Win32_Injector_gen_BT{
	meta:
		description = "VirTool:Win32/Injector.gen!BT,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {ff 31 ff 4d fc eb d8 ff 55 f4 } //01 00 
		$a_01_1 = {8a 06 46 32 45 f7 50 56 ff 45 } //01 00 
		$a_01_2 = {38 47 18 75 f3 80 3f 6b 74 07 80 3f 4b } //00 00 
	condition:
		any of ($a_*)
 
}