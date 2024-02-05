
rule VirTool_Win32_CeeInject_LP_bit{
	meta:
		description = "VirTool:Win32/CeeInject.LP!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {6b 56 8d 05 90 01 04 ff 10 a3 90 01 04 8d 3d 90 01 04 47 57 50 68 90 01 04 8b 90 01 02 c6 07 4c 90 09 08 00 8d 35 90 01 04 c6 06 90 00 } //01 00 
		$a_01_1 = {29 f6 4e 23 37 83 c7 04 f7 d6 f8 83 de 18 c1 ce 09 d1 c6 01 c6 8d 76 ff 29 c0 29 f0 f7 d8 c1 c0 09 d1 c8 56 8f 03 83 c3 04 83 c2 fc 85 d2 75 d0 } //00 00 
	condition:
		any of ($a_*)
 
}