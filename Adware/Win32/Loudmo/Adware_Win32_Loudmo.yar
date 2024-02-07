
rule Adware_Win32_Loudmo{
	meta:
		description = "Adware:Win32/Loudmo,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {41 00 64 00 77 00 41 00 64 00 42 00 72 00 46 00 72 00 6d 00 } //01 00  AdwAdBrFrm
		$a_01_1 = {6d 00 75 00 73 00 65 00 75 00 6d 00 } //01 00  museum
		$a_01_2 = {41 00 64 00 77 00 41 00 64 00 57 00 6e 00 64 00 } //0a 00  AdwAdWnd
		$a_02_3 = {2a 0c 3a 99 f7 fe 8a c1 8a 0d 90 01 04 fe c1 f6 2c 3a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Adware_Win32_Loudmo_2{
	meta:
		description = "Adware:Win32/Loudmo,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {70 61 72 74 6e 65 72 73 2e 61 64 74 65 6c 65 63 74 2e 63 6f 6d 2f 70 6f 73 74 2f 3f 43 65 6c 6c 49 44 3d } //01 00  partners.adtelect.com/post/?CellID=
		$a_01_1 = {77 65 62 73 65 61 72 63 68 2e 70 68 70 3f 73 72 63 3d 74 6f 70 73 26 73 65 61 72 63 68 3d } //01 00  websearch.php?src=tops&search=
		$a_01_2 = {3c 6b 65 79 3e 48 6f 6d 65 50 61 67 65 3c 2f 6b 65 79 3e } //01 00  <key>HomePage</key>
		$a_01_3 = {63 6f 6e 67 72 61 74 75 6c 61 74 69 6f 6e 73 2e 70 68 70 3f 61 66 66 3d } //02 00  congratulations.php?aff=
		$a_03_4 = {61 66 66 3d 22 90 02 08 22 20 2f 61 64 6f 6d 3d 22 90 02 08 22 20 2f 70 61 72 65 6e 74 3d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Adware_Win32_Loudmo_3{
	meta:
		description = "Adware:Win32/Loudmo,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 05 00 00 05 00 "
		
	strings :
		$a_03_0 = {83 c0 02 83 f8 2a 72 90 0a 20 00 33 c0 66 8b 90 02 04 8b 90 02 05 66 90 17 03 01 01 01 83 81 33 90 02 04 66 89 90 00 } //05 00 
		$a_03_1 = {83 c0 02 83 f8 10 72 90 0a 20 00 33 c0 66 8b 90 02 04 8b 90 02 05 66 90 17 03 01 01 01 83 81 33 90 02 04 66 89 90 00 } //05 00 
		$a_03_2 = {83 c0 02 83 f8 0e 72 90 0a 20 00 33 c0 66 8b 90 02 04 8b 90 02 05 66 90 17 03 01 01 01 83 81 33 90 02 04 66 89 90 00 } //03 00 
		$a_01_3 = {41 00 64 00 77 00 41 00 64 00 57 00 6e 00 64 00 } //03 00  AdwAdWnd
		$a_01_4 = {41 00 64 00 77 00 41 00 64 00 42 00 72 00 46 00 72 00 6d 00 } //00 00  AdwAdBrFrm
	condition:
		any of ($a_*)
 
}
rule Adware_Win32_Loudmo_4{
	meta:
		description = "Adware:Win32/Loudmo,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 02 00 "
		
	strings :
		$a_00_0 = {8b 16 0f b6 54 02 01 8b 4e 08 32 14 01 03 c8 88 51 01 8b 16 0f b6 54 02 02 8b 4e 08 32 54 01 01 03 c8 88 51 02 8b 16 0f b6 54 02 03 } //01 00 
		$a_00_1 = {69 6e 76 61 6c 69 64 20 76 65 63 74 6f 72 3c 74 3e 20 73 75 62 73 63 72 69 70 74 } //01 00  invalid vector<t> subscript
		$a_00_2 = {64 6c 6c 63 61 6e 75 6e 6c 6f 61 64 6e 6f 77 00 64 6c 6c 67 65 74 63 6c 61 73 73 6f 62 6a 65 63 74 00 64 6c 6c 72 65 67 69 73 74 65 72 73 65 72 76 65 72 00 64 6c 6c 75 6e 72 65 67 69 73 74 65 72 73 65 72 76 65 72 } //01 00 
		$a_01_3 = {70 00 72 00 6f 00 66 00 69 00 74 00 6d 00 75 00 73 00 65 00 } //00 00  profitmuse
	condition:
		any of ($a_*)
 
}
rule Adware_Win32_Loudmo_5{
	meta:
		description = "Adware:Win32/Loudmo,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 05 00 00 05 00 "
		
	strings :
		$a_01_0 = {4c 6f 75 64 4d 6f 20 43 6f 6e 74 65 78 74 75 61 6c 20 41 64 20 41 73 73 69 73 74 61 6e 74 } //01 00  LoudMo Contextual Ad Assistant
		$a_01_1 = {2f 73 65 74 75 70 2e 61 73 70 3f 72 65 73 3d 6f 6b 26 69 64 3d fd a8 80 22 2c 20 74 20 22 fd 9a 80 5c 6e 73 73 73 } //01 00 
		$a_01_2 = {2f 72 65 6d 6f 76 65 2e 61 73 70 3f 69 64 3d fd a8 80 22 2c 20 74 20 22 fd 9a 80 5c 75 6e 73 73 73 } //01 00 
		$a_01_3 = {52 31 2c 20 30 5d 3b 09 6a 2b 2b 09 7d 3b 09 74 5b 69 5d 20 3d 20 63 72 63 33 32 5f 72 65 66 6c 65 63 74 28 74 5b 69 5d 2c 20 33 32 29 3b 69 2b 2b 3b } //01 00 
		$a_01_4 = {00 61 61 61 37 33 30 38 65 2d 61 62 30 39 2d 34 63 37 38 2d 61 66 35 33 2d 31 38 63 32 37 38 34 62 33 64 62 65 00 } //00 00  愀慡㌷㠰ⵥ扡㤰㐭㝣ⴸ晡㌵ㄭ挸㜲㐸㍢扤e
	condition:
		any of ($a_*)
 
}
rule Adware_Win32_Loudmo_6{
	meta:
		description = "Adware:Win32/Loudmo,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_02_0 = {83 4d fc ff 8d 4d 88 a5 a5 e8 90 01 04 8b 45 08 8d 75 e4 8b f8 8b 4d f4 a5 a5 a5 a5 5f 5e 64 89 0d 00 00 00 00 c9 c3 90 00 } //01 00 
		$a_00_1 = {5c 00 4c 00 6f 00 63 00 61 00 6c 00 20 00 53 00 65 00 74 00 74 00 69 00 6e 00 67 00 73 00 5c 00 54 00 65 00 6d 00 70 00 6f 00 72 00 61 00 72 00 79 00 20 00 49 00 6e 00 74 00 65 00 72 00 6e 00 65 00 74 00 20 00 46 00 69 00 6c 00 65 00 73 00 5c 00 6c 00 6f 00 77 00 } //01 00  \Local Settings\Temporary Internet Files\low
		$a_00_2 = {44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77 00 44 6c 6c 47 65 74 43 6c 61 73 73 4f 62 6a 65 63 74 00 44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 00 44 6c 6c 55 6e 72 65 67 69 73 74 65 72 53 65 72 76 65 72 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Adware_Win32_Loudmo_7{
	meta:
		description = "Adware:Win32/Loudmo,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 02 00 "
		
	strings :
		$a_01_0 = {8b 16 0f b6 14 02 32 14 01 8b 7e 08 88 14 38 8b 16 0f b6 54 02 01 32 54 01 01 8b 7e 08 88 54 07 01 8b 16 0f b6 54 02 02 32 54 01 02 } //02 00 
		$a_00_1 = {5c 00 4c 00 6f 00 63 00 61 00 6c 00 20 00 53 00 65 00 74 00 74 00 69 00 6e 00 67 00 73 00 5c 00 54 00 65 00 6d 00 70 00 6f 00 72 00 61 00 72 00 79 00 20 00 49 00 6e 00 74 00 65 00 72 00 6e 00 65 00 74 00 20 00 46 00 69 00 6c 00 65 00 73 00 5c 00 6c 00 6f 00 77 00 } //01 00  \Local Settings\Temporary Internet Files\low
		$a_00_2 = {69 6e 76 61 6c 69 64 20 76 65 63 74 6f 72 3c 54 3e 20 73 75 62 73 63 72 69 70 74 } //01 00  invalid vector<T> subscript
		$a_00_3 = {44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77 00 44 6c 6c 47 65 74 43 6c 61 73 73 4f 62 6a 65 63 74 00 44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 00 44 6c 6c 55 6e 72 65 67 69 73 74 65 72 53 65 72 76 65 72 } //01 00 
		$a_00_4 = {4e 53 5f 46 72 65 65 00 78 70 63 6f 6d 2e 64 6c 6c 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Adware_Win32_Loudmo_8{
	meta:
		description = "Adware:Win32/Loudmo,SIGNATURE_TYPE_PEHSTR_EXT,39 00 38 00 10 00 00 32 00 "
		
	strings :
		$a_01_0 = {53 6f 66 74 77 61 72 65 5c 41 70 70 44 61 74 61 4c 6f 77 5c 48 61 76 69 6e 67 46 75 6e 4f 6e 6c 69 6e 65 } //05 00  Software\AppDataLow\HavingFunOnline
		$a_03_1 = {6c 6f 75 64 6d 6f 2e 90 02 10 2f 61 66 66 5f 69 3f 6f 66 66 65 72 5f 69 64 3d 90 02 03 26 61 66 66 5f 69 64 3d 90 00 } //02 00 
		$a_01_2 = {2f 75 73 72 2f 67 65 74 67 65 6f 69 70 69 6e 66 6f 2e 70 68 70 3f 67 75 70 3d } //02 00  /usr/getgeoipinfo.php?gup=
		$a_01_3 = {2f 75 73 72 2f 72 65 67 69 73 74 65 72 5f 73 76 63 2e 70 68 70 3f 67 75 70 3d } //01 00  /usr/register_svc.php?gup=
		$a_01_4 = {7b 53 65 61 72 63 68 54 65 72 6d 73 7d } //01 00  {SearchTerms}
		$a_01_5 = {77 65 62 73 65 61 72 63 68 2e 70 68 70 3f 73 72 63 3d 74 6f 70 73 26 73 65 61 72 63 68 3d } //01 00  websearch.php?src=tops&search=
		$a_01_6 = {3c 6b 65 79 3e 48 6f 6d 65 50 61 67 65 3c 2f 6b 65 79 3e } //01 00  <key>HomePage</key>
		$a_01_7 = {69 61 6d 77 69 72 65 64 2e 6e 65 74 } //01 00  iamwired.net
		$a_01_8 = {42 69 6e 67 2f 53 65 61 72 63 68 54 6f 6f 6c 62 61 72 2d 6c 6f 75 64 6d 6f 2e 65 78 65 } //01 00  Bing/SearchToolbar-loudmo.exe
		$a_01_9 = {42 69 6e 67 2f 53 65 61 72 63 68 54 6f 6f 6c 62 61 72 2d 66 6c 76 64 69 72 65 63 74 2e 65 78 65 } //01 00  Bing/SearchToolbar-flvdirect.exe
		$a_01_10 = {42 69 6e 67 2f 53 65 61 72 63 68 54 6f 6f 6c 62 61 72 2d 67 61 6d 65 62 6f 75 6e 64 2e 65 78 65 } //01 00  Bing/SearchToolbar-gamebound.exe
		$a_01_11 = {63 68 61 6d 65 6c 65 6f 6e 74 6f 6d 2e 63 6f 6d 2f 74 72 61 63 6b 2e 70 68 70 3f 76 3d } //01 00  chameleontom.com/track.php?v=
		$a_01_12 = {62 61 62 65 6c 66 69 73 68 6e 65 74 77 6f 72 6b 2e 63 6f 6d 2f 42 61 62 79 6c 6f 6e } //01 00  babelfishnetwork.com/Babylon
		$a_01_13 = {69 62 61 62 65 6c 66 69 73 68 2e 63 6f 6d 2f 42 61 62 79 6c 6f 6e } //01 00  ibabelfish.com/Babylon
		$a_01_14 = {42 69 6e 67 54 6f 6f 6c 62 61 72 2d 6c 6f 75 64 6d 6f 2e 65 78 65 } //9c ff  BingToolbar-loudmo.exe
		$a_01_15 = {72 65 67 69 73 74 65 72 40 68 61 76 69 6e 67 66 75 6e 6f 6e 6c 69 6e 65 2e 63 6f 6d } //00 00  register@havingfunonline.com
	condition:
		any of ($a_*)
 
}