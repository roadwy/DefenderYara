
rule VirTool_Win32_CeeInject_BDS_bit{
	meta:
		description = "VirTool:Win32/CeeInject.BDS!bit,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {c7 45 dc 6f 73 6f 66 } //01 00 
		$a_01_1 = {c7 45 e0 74 20 48 76 } //01 00 
		$a_01_2 = {c7 45 b8 58 65 6e 56 } //01 00 
		$a_01_3 = {c7 45 bc 4d 4d 58 65 } //01 00 
		$a_01_4 = {c7 45 c0 6e 56 4d 4d } //00 00 
	condition:
		any of ($a_*)
 
}