
rule TrojanClicker_Win32_RuPass{
	meta:
		description = "TrojanClicker:Win32/RuPass,SIGNATURE_TYPE_PEHSTR_EXT,32 00 32 00 10 00 00 01 00 "
		
	strings :
		$a_01_0 = {6d 79 2e 62 65 67 75 6e 2e 72 75 } //01 00  my.begun.ru
		$a_01_1 = {67 6f 6f 67 6c 65 2e 63 6f 6d 2f 61 64 73 65 6e 73 65 2f } //01 00  google.com/adsense/
		$a_01_2 = {70 72 6f 6d 6f 66 6f 72 75 6d 2e 72 75 } //01 00  promoforum.ru
		$a_01_3 = {73 65 6f 63 68 61 73 65 2e 63 6f 6d } //01 00  seochase.com
		$a_01_4 = {6d 61 73 74 65 72 74 61 6c 6b 2e 72 75 } //01 00  mastertalk.ru
		$a_01_5 = {73 65 61 72 63 68 65 6e 67 69 6e 65 73 2e 72 75 } //01 00  searchengines.ru
		$a_01_6 = {61 72 6d 61 64 61 62 6f 61 72 64 2e 63 6f 6d } //01 00  armadaboard.com
		$a_01_7 = {75 6d 61 78 66 6f 72 75 6d 2e 63 6f 6d } //01 00  umaxforum.com
		$a_01_8 = {75 6d 61 78 6c 6f 67 69 6e 2e 63 6f 6d } //01 00  umaxlogin.com
		$a_01_9 = {72 75 73 61 77 6d 2e 63 6f 6d } //01 00  rusawm.com
		$a_01_10 = {67 6f 66 75 63 6b 79 6f 75 72 73 65 6c 66 2e 63 6f 6d } //0a 00  gofuckyourself.com
		$a_01_11 = {43 6f 6e 6e 65 63 74 69 6f 6e 53 65 72 76 69 63 65 73 2e 43 6f 6e 6e 65 63 74 69 6f 6e 53 65 72 76 69 63 65 73 2e 31 5c 43 4c 53 49 44 } //0a 00  ConnectionServices.ConnectionServices.1\CLSID
		$a_01_12 = {54 79 70 65 4c 69 62 5c 7b 45 46 36 32 45 46 33 34 2d 37 45 35 41 2d 34 36 61 63 2d 39 33 38 33 2d 31 39 34 39 35 34 37 41 46 35 44 36 7d 5c 31 2e 30 5c 30 5c 77 69 6e 33 32 } //0a 00  TypeLib\{EF62EF34-7E5A-46ac-9383-1949547AF5D6}\1.0\0\win32
		$a_01_13 = {42 72 6f 77 73 65 72 20 48 65 6c 70 65 72 20 4f 62 6a 65 63 74 73 5c 7b 36 44 37 42 32 31 31 41 2d 38 38 45 41 2d 34 39 30 63 2d 42 41 42 39 2d 33 36 30 30 44 38 44 37 43 35 30 33 7d } //0a 00  Browser Helper Objects\{6D7B211A-88EA-490c-BAB9-3600D8D7C503}
		$a_01_14 = {43 6f 6e 6e 65 63 74 69 6f 6e 53 65 72 76 69 63 65 73 20 6d 6f 64 75 6c 65 } //0a 00  ConnectionServices module
		$a_01_15 = {52 65 6c 65 61 73 65 5c 52 75 50 61 73 73 2e 70 64 62 } //00 00  Release\RuPass.pdb
	condition:
		any of ($a_*)
 
}
rule TrojanClicker_Win32_RuPass_2{
	meta:
		description = "TrojanClicker:Win32/RuPass,SIGNATURE_TYPE_PEHSTR,1f 00 1f 00 08 00 00 0a 00 "
		
	strings :
		$a_01_0 = {52 75 50 61 73 73 2e 52 75 50 61 73 73 5c 43 75 72 56 65 72 00 00 00 00 52 75 50 61 73 73 2e 52 75 50 61 73 73 } //0a 00 
		$a_01_1 = {39 35 34 41 30 36 33 37 2d 39 31 34 37 2d 34 62 35 65 2d 39 36 34 45 2d 39 46 32 30 45 35 38 46 43 32 39 44 } //05 00  954A0637-9147-4b5e-964E-9F20E58FC29D
		$a_01_2 = {49 45 50 6c 75 67 69 6e 2e 44 4c 4c 00 52 75 6e 49 45 } //05 00  䕉汐杵湩䐮䱌刀湵䕉
		$a_01_3 = {45 41 45 34 34 38 32 36 2d 37 37 46 39 2d 34 66 62 30 2d 42 34 44 45 2d 31 35 35 32 45 32 36 32 36 42 37 33 } //05 00  EAE44826-77F9-4fb0-B4DE-1552E2626B73
		$a_01_4 = {31 32 39 32 33 34 31 32 2d 43 36 34 41 2d 34 38 63 66 2d 41 34 41 30 2d 36 37 38 31 32 34 35 44 43 39 35 32 } //05 00  12923412-C64A-48cf-A4A0-6781245DC952
		$a_01_5 = {45 30 41 41 38 45 32 42 2d 33 37 41 45 2d 34 32 66 35 2d 41 39 34 37 2d 35 43 31 34 37 43 41 35 39 33 33 38 } //01 00  E0AA8E2B-37AE-42f5-A947-5C147CA59338
		$a_01_6 = {43 6f 6e 66 69 67 4d 65 6d 6f 72 79 4d 61 70 70 69 6e 67 } //01 00  ConfigMemoryMapping
		$a_01_7 = {49 6e 74 65 72 6e 65 74 4f 70 65 6e 55 72 6c 41 } //00 00  InternetOpenUrlA
	condition:
		any of ($a_*)
 
}
rule TrojanClicker_Win32_RuPass_3{
	meta:
		description = "TrojanClicker:Win32/RuPass,SIGNATURE_TYPE_PEHSTR,10 00 10 00 11 00 00 01 00 "
		
	strings :
		$a_01_0 = {6d 79 2e 62 65 67 75 6e 2e 72 75 } //01 00  my.begun.ru
		$a_01_1 = {70 72 6f 6d 6f 66 6f 72 75 6d 2e 72 75 } //01 00  promoforum.ru
		$a_01_2 = {73 65 6f 63 68 61 73 65 2e 63 6f 6d } //01 00  seochase.com
		$a_01_3 = {6d 61 73 74 65 72 74 61 6c 6b 2e 72 75 } //01 00  mastertalk.ru
		$a_01_4 = {73 65 61 72 63 68 65 6e 67 69 6e 65 73 2e 72 75 } //01 00  searchengines.ru
		$a_01_5 = {61 72 6d 61 64 61 62 6f 61 72 64 2e 63 6f 6d } //01 00  armadaboard.com
		$a_01_6 = {75 6d 61 78 66 6f 72 75 6d 2e 63 6f 6d } //01 00  umaxforum.com
		$a_01_7 = {75 6d 61 78 6c 6f 67 69 6e 2e 63 6f 6d } //01 00  umaxlogin.com
		$a_01_8 = {72 75 73 61 77 6d 2e 63 6f 6d } //01 00  rusawm.com
		$a_01_9 = {67 6f 66 75 63 6b 79 6f 75 72 73 65 6c 66 2e 63 6f 6d } //01 00  gofuckyourself.com
		$a_01_10 = {49 6e 73 74 61 6e 63 65 52 75 6e 43 6f 6e 74 72 6f 6c 4d 75 74 65 78 } //04 00  InstanceRunControlMutex
		$a_01_11 = {43 6f 6e 6e 65 63 74 69 6f 6e 53 65 72 76 69 63 65 73 } //04 00  ConnectionServices
		$a_01_12 = {45 46 36 32 45 46 33 34 2d 37 45 35 41 2d 34 36 61 63 2d 39 33 38 33 2d 31 39 34 39 35 34 37 41 46 35 44 36 } //04 00  EF62EF34-7E5A-46ac-9383-1949547AF5D6
		$a_01_13 = {36 44 37 42 32 31 31 41 2d 38 38 45 41 2d 34 39 30 63 2d 42 41 42 39 2d 33 36 30 30 44 38 44 37 43 35 30 33 } //04 00  6D7B211A-88EA-490c-BAB9-3600D8D7C503
		$a_01_14 = {52 65 6c 65 61 73 65 5c 52 75 50 61 73 73 2e 70 64 62 } //05 00  Release\RuPass.pdb
		$a_01_15 = {72 75 70 61 73 73 2e 63 6f 6d 2f 61 62 6f 75 74 } //06 00  rupass.com/about
		$a_01_16 = {00 52 75 50 61 73 73 20 25 73 00 } //00 00 
	condition:
		any of ($a_*)
 
}