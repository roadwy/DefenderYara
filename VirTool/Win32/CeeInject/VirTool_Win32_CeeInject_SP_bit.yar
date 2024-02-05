
rule VirTool_Win32_CeeInject_SP_bit{
	meta:
		description = "VirTool:Win32/CeeInject.SP!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {81 fe d8 a6 08 00 7f 14 81 fe 50 f5 00 00 7d 09 50 ff d7 6a 00 ff d3 33 c0 46 eb e4 } //01 00 
		$a_01_1 = {8b cb c1 e9 10 88 0e 46 8b c3 c1 e8 08 88 06 46 88 1e 46 33 db 88 5d 0b } //01 00 
		$a_03_2 = {8b 75 08 57 8b 7d 0c e8 90 01 04 30 04 3e 5f 5e 5d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}