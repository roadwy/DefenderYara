
rule VirTool_Win32_CeeInject_ABN_bit{
	meta:
		description = "VirTool:Win32/CeeInject.ABN!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {6b 00 66 c7 45 90 01 01 65 00 66 c7 45 90 01 01 72 00 66 c7 45 90 01 01 6e 00 66 c7 45 90 01 01 65 00 66 c7 45 90 01 01 6c 00 66 c7 45 90 01 01 33 00 66 c7 45 90 01 01 32 00 66 c7 45 90 01 01 2e 00 66 c7 45 90 01 01 64 00 66 c7 45 90 01 01 6c 00 66 c7 45 90 01 01 6c 00 66 c7 45 90 01 01 00 00 90 00 } //01 00 
		$a_01_1 = {8a 1c 30 80 f3 0e f6 d3 80 f3 cf 88 1c 30 } //00 00 
	condition:
		any of ($a_*)
 
}