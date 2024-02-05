
rule VirTool_Win32_CeeInject_gen_GD{
	meta:
		description = "VirTool:Win32/CeeInject.gen!GD,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {56 8b cf 80 f3 08 e8 90 01 04 46 88 18 83 fe 90 01 01 72 e7 90 00 } //01 00 
		$a_01_1 = {c7 07 08 00 01 00 ff 0f } //01 00 
		$a_01_2 = {8b 46 0c 03 43 34 } //01 00 
	condition:
		any of ($a_*)
 
}