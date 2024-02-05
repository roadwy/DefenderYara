
rule VirTool_WinNT_Nedsym_gen_F{
	meta:
		description = "VirTool:WinNT/Nedsym.gen!F,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {44 00 65 00 76 00 69 00 63 00 65 00 5c 00 53 00 53 00 44 00 54 00 } //01 00 
		$a_01_1 = {68 1c 07 01 00 8d 4d d4 51 ff 15 9c 08 01 00 8d 55 e0 52 6a 00 68 00 01 00 00 68 20 04 00 00 8d 45 f8 50 6a 00 8b 4d 08 51 ff 15 a4 08 01 00 } //00 00 
	condition:
		any of ($a_*)
 
}