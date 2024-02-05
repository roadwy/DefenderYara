
rule VirTool_Win32_CeeInject_SX_bit{
	meta:
		description = "VirTool:Win32/CeeInject.SX!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {8a 07 c1 e0 02 33 d2 8a 57 01 c1 ea 04 0a c2 8b 15 90 01 04 8b 0e 88 04 0a e8 90 01 04 ff 06 ff 05 90 01 04 4b 75 90 00 } //01 00 
		$a_03_1 = {75 34 8a 15 90 01 04 c1 e2 04 25 90 01 04 c1 e8 02 0a d0 a1 90 01 04 8b 0d 90 01 04 88 54 08 01 8b 15 90 01 04 83 c2 02 ff 05 90 01 04 8b c2 90 00 } //01 00 
		$a_03_2 = {33 db 8a da 83 fb 3d 7f 90 01 01 74 90 01 01 83 eb 2b 74 90 01 01 83 eb 04 74 90 01 01 4b 83 eb 0a 72 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}