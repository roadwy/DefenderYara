
rule Backdoor_Win32_Mdmbot_G_loader{
	meta:
		description = "Backdoor:Win32/Mdmbot.G!loader!dha,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 05 00 00 05 00 "
		
	strings :
		$a_03_0 = {68 01 00 00 80 ff 15 90 01 04 8d 54 24 08 52 ff 15 90 01 04 8b 4c 24 00 50 8d 44 24 0c 50 6a 01 6a 00 68 90 01 04 51 ff 15 90 01 03 00 8b 54 24 00 52 ff 15 90 01 04 8d 44 24 08 6a 05 50 ff 15 90 00 } //01 00 
		$a_02_1 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 41 63 74 69 76 65 20 53 65 74 75 70 5c 49 6e 73 74 61 6c 6c 65 64 20 43 6f 6d 70 6f 6e 65 6e 74 73 5c 7b 90 01 08 2d 90 01 04 2d 90 01 04 2d 90 01 04 2d 90 01 0c 7d 90 00 } //01 00 
		$a_00_2 = {22 00 25 00 73 00 22 00 20 00 2f 00 49 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 00 00 00 00 00 00 63 00 74 00 66 00 6d 00 6f 00 6d 00 } //01 00 
		$a_00_3 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //05 00  Software\Microsoft\Windows\CurrentVersion\Run
		$a_10_4 = {43 3a 5c 44 6f 63 75 6d 65 6e 74 73 20 61 6e 64 20 53 65 74 74 69 6e 67 73 5c 41 64 6d 69 6e 69 73 74 72 61 74 6f 72 5c 41 6c 69 61 70 70 2e 65 78 65 } //00 00  C:\Documents and Settings\Administrator\Aliapp.exe
		$a_00_5 = {5d 04 00 00 81 69 } //03 80 
	condition:
		any of ($a_*)
 
}