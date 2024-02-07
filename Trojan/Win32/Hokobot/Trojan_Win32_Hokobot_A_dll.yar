
rule Trojan_Win32_Hokobot_A_dll{
	meta:
		description = "Trojan:Win32/Hokobot.A.dll!dha,SIGNATURE_TYPE_PEHSTR_EXT,33 00 33 00 07 00 00 0a 00 "
		
	strings :
		$a_01_0 = {3c 28 74 10 3c 29 74 0c 3c 2e 74 08 3c 20 74 04 3c } //0a 00 
		$a_00_1 = {38 32 42 44 30 45 36 37 2d 39 46 45 41 2d 34 37 34 38 2d 38 36 37 32 2d 44 35 45 46 45 35 42 37 37 39 42 30 } //0a 00  82BD0E67-9FEA-4748-8672-D5EFE5B779B0
		$a_00_2 = {32 32 30 64 35 63 63 31 } //0a 00  220d5cc1
		$a_00_3 = {62 39 38 31 39 63 35 32 } //0a 00  b9819c52
		$a_00_4 = {4c 00 24 00 5f 00 52 00 61 00 73 00 44 00 65 00 66 00 61 00 75 00 6c 00 74 00 43 00 72 00 65 00 64 00 65 00 6e 00 74 00 69 00 61 00 6c 00 73 00 23 00 30 00 } //0a 00  L$_RasDefaultCredentials#0
		$a_01_5 = {53 65 74 57 69 6e 48 6f 4b } //01 00  SetWinHoK
		$a_00_6 = {5c 41 70 70 6c 69 63 61 74 69 6f 6e 20 44 61 74 61 5c 4d 69 63 72 6f 73 6f 66 74 5c 4e 65 74 77 6f 72 6b 5c 43 6f 6e 6e 65 63 74 69 6f 6e 73 5c 70 62 6b 5c 72 61 73 70 68 6f 6e 65 2e 70 62 6b } //00 00  \Application Data\Microsoft\Network\Connections\pbk\rasphone.pbk
		$a_00_7 = {5d 04 00 00 46 33 03 80 5c 29 00 00 47 33 03 80 00 00 01 00 08 00 13 00 ac 21 48 6f 6b 6f 62 6f 74 2e 42 2e 64 6c 6c 21 64 68 61 00 00 01 40 05 82 70 } //00 04 
	condition:
		any of ($a_*)
 
}