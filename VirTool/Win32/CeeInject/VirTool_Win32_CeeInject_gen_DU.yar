
rule VirTool_Win32_CeeInject_gen_DU{
	meta:
		description = "VirTool:Win32/CeeInject.gen!DU,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {46 69 6e 64 52 65 73 6f 75 72 63 65 41 00 } //01 00 
		$a_00_1 = {4c 6f 61 64 52 65 73 6f 75 72 63 65 00 } //01 00 
		$a_00_2 = {43 72 65 61 74 65 50 72 6f 63 65 73 73 41 00 } //01 00 
		$a_00_3 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 00 } //01 00 
		$a_01_4 = {8a 04 32 30 01 ff 45 fc 8b 45 fc 3b 45 10 7c ad } //00 00 
	condition:
		any of ($a_*)
 
}