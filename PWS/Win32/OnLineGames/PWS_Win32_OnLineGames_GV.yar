
rule PWS_Win32_OnLineGames_GV{
	meta:
		description = "PWS:Win32/OnLineGames.GV,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {2f 70 6f 62 61 6f 2f 47 65 74 54 75 50 69 61 6e 2e 61 73 70 } //01 00  /pobao/GetTuPian.asp
		$a_00_1 = {3f 41 3d 25 73 26 42 3d 25 73 26 45 3d 25 73 26 49 3d 25 73 } //02 00  ?A=%s&B=%s&E=%s&I=%s
		$a_01_2 = {6a 04 6a 30 68 b0 2f 4b 00 } //02 00 
		$a_01_3 = {3d 56 8b 74 24 74 0f 68 e8 03 00 00 } //00 00 
	condition:
		any of ($a_*)
 
}