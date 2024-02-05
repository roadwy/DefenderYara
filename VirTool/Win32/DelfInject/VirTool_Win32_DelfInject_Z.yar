
rule VirTool_Win32_DelfInject_Z{
	meta:
		description = "VirTool:Win32/DelfInject.Z,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {74 0f 31 d2 8a 16 01 d3 48 8d 76 01 8d 3c 3b 7f f1 } //01 00 
		$a_01_1 = {7c 31 8d 6f ff 89 d8 c1 e8 02 83 e0 07 29 c5 8a 06 46 } //01 00 
	condition:
		any of ($a_*)
 
}