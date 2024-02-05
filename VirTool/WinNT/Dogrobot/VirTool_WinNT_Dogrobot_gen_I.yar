
rule VirTool_WinNT_Dogrobot_gen_I{
	meta:
		description = "VirTool:WinNT/Dogrobot.gen!I,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {c6 03 2b c7 43 01 e1 c1 e9 02 8b 1d 90 01 02 01 00 8d 45 f0 90 00 } //01 00 
		$a_01_1 = {81 38 59 68 e8 03 75 3a 81 78 04 00 00 e8 0e 75 31 8b 45 04 3d 00 00 00 80 72 27 80 38 83 75 22 80 78 01 4d 75 1c 80 78 02 fc 75 16 80 78 03 ff 75 10 80 78 04 6a ff 75 fc e8 } //01 00 
		$a_03_2 = {8b 0c b3 0b c9 74 25 8b 79 04 66 8b 07 66 83 f8 03 75 19 8b 47 10 0b c0 74 12 a3 90 01 02 01 00 89 3d 90 01 02 01 00 33 c0 89 47 10 eb 08 83 c6 01 83 fe 26 72 cc 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}