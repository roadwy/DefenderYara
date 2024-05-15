
rule Trojan_Win32_Hokobot_A_dha{
	meta:
		description = "Trojan:Win32/Hokobot.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,29 00 29 00 05 00 00 0a 00 "
		
	strings :
		$a_03_0 = {81 7d 0c 04 01 00 00 74 90 01 01 81 7d 0c 00 01 00 00 90 00 } //0a 00 
		$a_01_1 = {23 23 44 61 74 61 23 23 3a 20 41 63 74 69 76 65 20 57 69 6e 64 6f 77 2d 2d 3e } //0a 00  ##Data##: Active Window-->
		$a_01_2 = {53 65 74 57 69 6e 48 6f 4b } //0a 00  SetWinHoK
		$a_01_3 = {3c 73 74 72 6f 6e 67 3e 20 5b 43 41 50 4c 4f 43 4b 5d 20 3c 2f 73 74 72 6f 6e 67 3e } //01 00  <strong> [CAPLOCK] </strong>
		$a_01_4 = {5c 73 65 72 76 65 72 68 65 6c 70 2e 64 6c 6c } //00 00  \serverhelp.dll
		$a_00_5 = {5d 04 00 00 44 33 03 80 5c 25 00 00 45 33 03 80 00 00 01 00 08 00 0f 00 ac 21 48 6f 6b 6f 62 6f 74 2e 42 21 64 68 61 00 } //00 02 
	condition:
		any of ($a_*)
 
}