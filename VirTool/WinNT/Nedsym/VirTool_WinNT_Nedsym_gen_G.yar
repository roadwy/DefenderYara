
rule VirTool_WinNT_Nedsym_gen_G{
	meta:
		description = "VirTool:WinNT/Nedsym.gen!G,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {5c 00 44 00 6f 00 73 00 44 00 65 00 76 00 69 00 63 00 65 00 73 00 5c 00 48 00 69 00 64 00 65 00 50 00 6f 00 72 00 74 00 } //01 00 
		$a_13_1 = {45 f4 33 db 50 89 5d fc ff d7 8b 75 08 8d 45 fc 50 53 53 6a 22 8d 45 f4 50 53 56 ff 15 90 01 04 3b c3 89 45 08 90 00 01 } //00 1f 
		$a_8b_2 = {08 c1 e1 02 51 ff 30 53 ff 15 2c 20 01 00 a3 90 01 04 3b } //c3 75 
		$a_b8_3 = {00 00 c0 90 00 00 00 } //5d 04 
	condition:
		any of ($a_*)
 
}