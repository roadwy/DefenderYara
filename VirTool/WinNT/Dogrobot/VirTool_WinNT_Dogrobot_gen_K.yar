
rule VirTool_WinNT_Dogrobot_gen_K{
	meta:
		description = "VirTool:WinNT/Dogrobot.gen!K,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 6f 49 79 4d 50 33 c0 50 ff 15 } //01 00 
		$a_01_1 = {77 2f 81 38 8b ff 55 8b 75 1b 81 78 04 ec 56 64 a1 75 12 81 78 08 24 01 00 00 75 09 81 78 0c 8b 75 08 3b 74 07 } //01 00 
		$a_03_2 = {51 50 0f 20 c0 89 44 24 04 25 ff ff fe ff 0f 22 c0 58 fa 8b 04 24 a3 90 01 04 59 c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}