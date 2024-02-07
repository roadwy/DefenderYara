
rule Trojan_Win32_Startpage_WG{
	meta:
		description = "Trojan:Win32/Startpage.WG,SIGNATURE_TYPE_PEHSTR,05 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {57 69 6e 47 61 6d 65 73 2e 6c 6e 6b } //01 00  WinGames.lnk
		$a_01_1 = {43 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 57 69 6e 47 61 6d 65 73 5c 62 62 2e 74 6d 70 } //01 00  C:\Program Files\WinGames\bb.tmp
		$a_01_2 = {43 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 57 69 6e 47 61 6d 65 73 5c 77 69 6e 67 61 6d 65 73 2e 65 78 65 } //01 00  C:\Program Files\WinGames\wingames.exe
		$a_01_3 = {43 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 57 69 6e 47 61 6d 65 73 5c 51 76 6f 64 53 65 74 75 70 50 6c 75 73 2e 65 78 65 } //01 00  C:\Program Files\WinGames\QvodSetupPlus.exe
		$a_01_4 = {73 6f 31 2e 35 6b 35 2e 6e 65 74 2f 69 6e 74 65 72 66 61 63 65 } //00 00  so1.5k5.net/interface
	condition:
		any of ($a_*)
 
}