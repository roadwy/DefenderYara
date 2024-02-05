
rule VirTool_Win32_Lodrypt_A_dr{
	meta:
		description = "VirTool:Win32/Lodrypt.A!dr,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_02_0 = {33 ff eb 1b 90 01 03 32 c9 b8 90 01 04 fe c1 30 08 40 3d 90 01 04 7e f6 e9 90 01 02 00 00 bb 90 01 04 66 b8 99 99 57 ff d3 90 00 } //01 00 
		$a_02_1 = {ff ff 6a 0a 68 90 01 04 e8 90 01 02 ff ff 8d 55 e0 33 c0 e8 90 01 02 ff ff 8b 45 e0 8d 55 e4 e8 90 01 02 ff ff 8d 45 e4 ba 90 01 04 e8 90 01 02 ff ff 8b 45 e4 e8 90 01 02 ff ff 33 c0 5a 59 59 64 89 10 90 00 } //01 00 
		$a_00_2 = {52 54 5f 52 43 44 41 54 41 00 00 00 43 4f 4e 54 45 4e 54 00 } //00 00 
	condition:
		any of ($a_*)
 
}