
rule VirTool_Win32_CeeInject_SB_bit{
	meta:
		description = "VirTool:Win32/CeeInject.SB!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {33 d8 8b 45 fc 69 c0 90 01 04 99 b9 90 01 04 f7 f9 88 9c 05 90 01 04 8b 45 fc 69 c0 90 01 04 99 b9 90 01 04 f7 f9 33 d2 8a 94 05 90 01 04 83 fa 90 00 } //01 00 
		$a_03_1 = {8b 45 fc 69 c0 90 01 04 99 b9 90 01 04 f7 f9 33 d2 8a 94 05 90 01 04 8b ca 83 e9 01 8b 45 fc 69 c0 90 01 04 99 be 90 01 04 f7 fe 88 8c 05 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}