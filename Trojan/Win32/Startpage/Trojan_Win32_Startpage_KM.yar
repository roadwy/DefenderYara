
rule Trojan_Win32_Startpage_KM{
	meta:
		description = "Trojan:Win32/Startpage.KM,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 43 6f 6d 6d 6f 6e 20 46 69 6c 65 73 5c 69 65 78 70 6c 6f 72 65 2e 65 78 65 20 25 31 20 68 25 74 25 74 25 70 3a 25 2f 2f 25 77 25 77 25 77 2e } //01 00  C:\Program Files\Common Files\iexplore.exe %1 h%t%t%p:%//%w%w%w.
		$a_01_1 = {53 4f 46 54 57 41 52 45 5c 43 6c 61 73 73 65 73 5c 43 4c 53 49 44 5c 7b 65 31 37 64 34 66 63 30 2d 35 35 36 34 2d 31 31 64 31 2d 38 33 66 32 2d 30 30 61 30 63 39 30 64 63 38 34 39 7d 5c 53 68 65 6c 6c 5c 4f 70 65 6e 28 26 4f 29 } //01 00  SOFTWARE\Classes\CLSID\{e17d4fc0-5564-11d1-83f2-00a0c90dc849}\Shell\Open(&O)
		$a_01_2 = {72 65 6d 6f 76 65 20 6d 79 73 65 6c 66 20 66 61 69 6c 65 20 21 } //00 00  remove myself faile !
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Startpage_KM_2{
	meta:
		description = "Trojan:Win32/Startpage.KM,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 04 00 00 0a 00 "
		
	strings :
		$a_02_0 = {8d 4c 24 10 51 6a 00 68 65 04 00 00 53 ff 15 90 01 04 a1 90 01 04 8d 04 40 8d 04 80 8d 04 80 8d 04 80 8d 14 80 c1 e2 05 52 ff d5 90 00 } //01 00 
		$a_00_1 = {7b 00 38 00 38 00 35 00 36 00 46 00 39 00 36 00 31 00 2d 00 33 00 34 00 30 00 41 00 2d 00 31 00 31 00 44 00 30 00 2d 00 41 00 39 00 36 00 42 00 2d 00 30 00 30 00 43 00 30 00 34 00 46 00 44 00 37 00 30 00 35 00 41 00 32 00 7d 00 } //01 00  {8856F961-340A-11D0-A96B-00C04FD705A2}
		$a_02_2 = {68 74 74 70 3a 2f 2f 67 67 90 01 01 2e 38 64 61 6f 2e 69 6e 66 6f 90 00 } //01 00 
		$a_01_3 = {b0 c1 d3 ce e4 af c0 c0 c6 f7 32 2e 6c 6e 6b } //00 00 
	condition:
		any of ($a_*)
 
}