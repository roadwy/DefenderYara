
rule VirTool_WinNT_Nedsym_gen_E{
	meta:
		description = "VirTool:WinNT/Nedsym.gen!E,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {44 00 65 00 76 00 69 00 63 00 65 00 73 00 5c 00 48 00 69 00 64 00 65 00 50 00 6f 00 72 00 74 00 } //01 00  Devices\HidePort
		$a_01_1 = {8b 3d 08 10 01 00 68 00 40 01 00 8d 45 f4 33 db 50 89 5d fc ff d7 8b 75 08 8d 45 fc 50 53 53 6a 22 8d 45 f4 50 53 56 ff 15 30 10 01 00 } //00 00 
	condition:
		any of ($a_*)
 
}