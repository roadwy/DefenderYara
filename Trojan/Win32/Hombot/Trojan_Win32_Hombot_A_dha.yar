
rule Trojan_Win32_Hombot_A_dha{
	meta:
		description = "Trojan:Win32/Hombot.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 06 00 00 05 00 "
		
	strings :
		$a_01_0 = {75 73 65 72 6e 61 6d 65 3d 37 37 64 61 39 31 35 35 61 63 33 66 37 38 37 38 37 66 65 36 30 63 66 64 63 37 38 34 38 34 35 64 26 70 61 73 73 77 6f 72 64 3d 63 38 31 30 38 38 30 35 38 33 30 33 65 65 31 35 39 39 32 30 33 31 32 37 65 35 33 65 65 30 66 63 26 62 75 74 74 6f 6e 3d 4c 6f 67 69 6e } //05 00  username=77da9155ac3f78787fe60cfdc784845d&password=c81088058303ee1599203127e53ee0fc&button=Login
		$a_01_1 = {43 3a 5c 55 73 65 72 73 5c 78 6d 61 6e 5f 31 33 36 35 5f 78 5c 44 65 73 6b 74 6f 70 } //01 00  C:\Users\xman_1365_x\Desktop
		$a_01_2 = {26 74 74 79 70 65 3d 31 30 32 26 73 74 61 74 65 3d 33 30 31 26 49 44 4f 50 3d } //01 00  &ttype=102&state=301&IDOP=
		$a_01_3 = {26 74 74 79 70 65 3d 31 30 32 26 73 74 61 74 65 3d 32 30 31 } //01 00  &ttype=102&state=201
		$a_01_4 = {5c 64 65 73 6b 63 61 70 74 75 72 65 2e 62 6d 70 } //01 00  \deskcapture.bmp
		$a_01_5 = {5c 64 65 73 6b 63 61 70 74 75 72 65 2e 6a 70 67 } //00 00  \deskcapture.jpg
		$a_00_6 = {5d 04 00 } //00 cc 
	condition:
		any of ($a_*)
 
}