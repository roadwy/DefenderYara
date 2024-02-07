
rule TrojanDownloader_Win32_BHO_A{
	meta:
		description = "TrojanDownloader:Win32/BHO.A,SIGNATURE_TYPE_PEHSTR,34 00 34 00 0a 00 00 0a 00 "
		
	strings :
		$a_01_0 = {8a 16 30 c2 d1 ea 73 02 31 fa 41 80 e1 07 75 f4 c1 e8 08 31 d0 46 80 3e 00 75 } //0a 00 
		$a_01_1 = {30 30 45 42 42 33 42 33 2d 44 45 41 44 2d 34 34 34 30 2d 42 31 46 38 2d 42 30 39 44 44 44 42 38 39 45 46 33 } //0a 00  00EBB3B3-DEAD-4440-B1F8-B09DDDB89EF3
		$a_01_2 = {45 78 69 74 57 69 6e 64 6f 77 73 45 78 } //0a 00  ExitWindowsEx
		$a_01_3 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //0a 00  DllRegisterServer
		$a_01_4 = {53 65 53 68 75 74 64 6f 77 6e 50 72 69 76 69 6c 65 67 65 } //01 00  SeShutdownPrivilege
		$a_01_5 = {6b 61 76 32 } //01 00  kav2
		$a_01_6 = {69 6e 6a 65 63 74 } //01 00  inject
		$a_01_7 = {64 6e 73 6d 61 73 6b } //01 00  dnsmask
		$a_01_8 = {50 6f 73 74 44 65 6c } //01 00  PostDel
		$a_01_9 = {70 61 73 73 77 6f 72 64 } //00 00  password
	condition:
		any of ($a_*)
 
}