
rule VirTool_Win32_VBInject_gen_HP{
	meta:
		description = "VirTool:Win32/VBInject.gen!HP,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {c7 02 07 00 01 00 } //01 00 
		$a_01_1 = {89 8a b0 00 00 00 } //01 00 
		$a_03_2 = {8b 91 a4 00 00 00 90 02 05 c7 85 90 01 02 ff ff 03 00 00 90 00 } //01 00 
		$a_03_3 = {66 0f b6 0c 08 8b 95 90 01 02 ff ff 8b 45 90 01 01 66 33 0c 50 90 00 } //01 00 
	condition:
		any of ($a_*)
 
}