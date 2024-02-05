
rule VirTool_Win32_Obfuscator_QF{
	meta:
		description = "VirTool:Win32/Obfuscator.QF,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {27 fd fe fc 2e fd fb fc 3d fd e7 fc 4c fd e4 fc fe fc e0 fc 1a 30 19 31 09 41 08 46 38 56 27 57 f9 fc 22 fd fe fc } //01 00 
		$a_01_1 = {2b fd fe fc 59 fd fb fc 4e fd fa fc fe fc f9 fc 1a a0 19 a1 09 b1 08 b6 38 c6 27 c7 38 d6 27 d7 } //01 00 
		$a_01_2 = {28 fd fe fc 4a fd fb fc 3d fd e7 fc 4f fd e4 fc } //00 00 
	condition:
		any of ($a_*)
 
}