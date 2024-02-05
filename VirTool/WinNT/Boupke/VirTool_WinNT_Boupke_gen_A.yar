
rule VirTool_WinNT_Boupke_gen_A{
	meta:
		description = "VirTool:WinNT/Boupke.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {eb 37 8d 45 e4 50 ff 75 f8 ff 75 fc 6a 05 ff 15 90 01 02 01 00 3b c3 89 45 ec 7d 34 90 01 57 f3 a6 74 0e 90 01 25 b8 25 02 00 c0 eb a6 90 00 } //01 00 
		$a_03_1 = {e9 d9 00 00 00 68 41 df 5c 02 ff 15 90 01 02 01 00 50 51 52 56 57 fa 0f 20 c0 89 45 fc 25 ff ff fe ff 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}