
rule VirTool_Win32_VBInject_gen_AP{
	meta:
		description = "VirTool:Win32/VBInject.gen!AP,SIGNATURE_TYPE_PEHSTR_EXT,07 00 06 00 05 00 00 02 00 "
		
	strings :
		$a_01_0 = {66 81 7d a8 4d 5a 74 55 } //02 00 
		$a_01_1 = {81 bd ac fe ff ff 50 45 00 00 0f 84 b9 00 00 00 } //02 00 
		$a_01_2 = {75 2f 8b 8d fc fe ff ff 8b 95 e0 fe ff ff 8b 85 7c fd ff ff 6a 04 68 00 30 00 00 51 52 50 e8 } //01 00 
		$a_00_3 = {43 00 61 00 6e 00 20 00 6e 00 6f 00 74 00 20 00 73 00 74 00 61 00 72 00 74 00 20 00 76 00 69 00 63 00 74 00 69 00 6d 00 20 00 70 00 72 00 6f 00 63 00 65 00 73 00 73 00 21 00 } //01 00  Can not start victim process!
		$a_00_4 = {2f 00 28 00 2a 00 29 00 5c 00 } //00 00  /(*)\
	condition:
		any of ($a_*)
 
}