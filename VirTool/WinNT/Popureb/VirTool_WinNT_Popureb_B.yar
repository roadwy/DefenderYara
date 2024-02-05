
rule VirTool_WinNT_Popureb_B{
	meta:
		description = "VirTool:WinNT/Popureb.B,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {80 7e 30 2a 75 0b c7 46 0c 40 00 00 00 c6 46 30 28 } //01 00 
		$a_01_1 = {48 6f 6f 6b 41 74 61 70 69 53 74 61 72 74 49 4f 2c 20 4e 55 4c 4c 20 3d 3d 20 52 65 61 6c 44 69 73 6b } //00 00 
	condition:
		any of ($a_*)
 
}