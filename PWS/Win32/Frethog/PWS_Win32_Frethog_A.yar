
rule PWS_Win32_Frethog_A{
	meta:
		description = "PWS:Win32/Frethog.A,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0c 00 0a 00 00 01 00 "
		
	strings :
		$a_00_0 = {57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 55 4e } //02 00  Windows\CurrentVersion\RUN
		$a_00_1 = {41 56 50 2e 50 72 6f 64 75 63 74 5f 4e 6f 74 69 66 69 63 61 74 69 4f 6e } //02 00  AVP.Product_NotificatiOn
		$a_00_2 = {41 56 50 2e 41 6c 65 72 74 44 69 61 6c 6f 47 } //01 00  AVP.AlertDialoG
		$a_00_3 = {65 78 70 6c 6f 72 65 72 2e 65 78 65 } //02 00  explorer.exe
		$a_00_4 = {25 73 20 25 63 25 73 25 63 25 64 } //02 00  %s %c%s%c%d
		$a_00_5 = {57 57 68 01 02 00 00 53 ff d6 57 57 68 02 02 00 00 53 ff d6 } //02 00 
		$a_01_6 = {c8 f0 d0 c7 d7 a2 b2 e1 b1 ed bc e0 bf d8 cc e1 } //01 00 
		$a_01_7 = {43 72 65 61 74 65 54 6f 6f 6c 68 65 6c 70 33 32 53 6e 61 70 73 68 6f 74 } //01 00  CreateToolhelp32Snapshot
		$a_01_8 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //01 00  WriteProcessMemory
		$a_00_9 = {4c 6f 61 64 52 65 73 6f 75 72 63 65 } //00 00  LoadResource
	condition:
		any of ($a_*)
 
}
rule PWS_Win32_Frethog_A_2{
	meta:
		description = "PWS:Win32/Frethog.A,SIGNATURE_TYPE_PEHSTR,14 00 11 00 0d 00 00 02 00 "
		
	strings :
		$a_01_0 = {25 73 3f 61 3d 31 26 73 72 76 3d 25 73 26 69 64 3d 25 73 26 } //02 00  %s?a=1&srv=%s&id=%s&
		$a_01_1 = {70 3d 25 73 26 73 3d 25 73 26 73 73 3d 25 73 26 6a 73 3d 25 73 } //02 00  p=%s&s=%s&ss=%s&js=%s
		$a_01_2 = {26 67 6a 3d 25 73 26 64 6a 3d 25 64 26 79 7a 3d 25 64 } //02 00  &gj=%s&dj=%d&yz=%d
		$a_01_3 = {26 79 7a 3d 25 64 00 6b 65 72 6e 65 6c 33 32 } //02 00 
		$a_01_4 = {46 6f 72 74 68 67 6f 72 72 } //01 00  Forthgorr
		$a_01_5 = {4f 70 65 6e 54 68 72 65 61 64 } //02 00  OpenThread
		$a_01_6 = {54 68 72 65 61 64 00 00 73 65 72 76 65 72 6e 61 } //01 00 
		$a_01_7 = {2e 5c 63 6f 6e 66 69 67 2e 69 6e 69 } //02 00  .\config.ini
		$a_01_8 = {25 73 3f 61 3d 25 64 26 73 3d 25 73 26 75 3d 25 73 26 70 3d 25 73 26 72 3d 25 73 26 6c 3d 25 64 26 6d 3d 25 64 } //02 00  %s?a=%d&s=%s&u=%s&p=%s&r=%s&l=%d&m=%d
		$a_01_9 = {77 73 32 5f c7 45 } //02 00 
		$a_01_10 = {49 73 44 65 c7 45 } //02 00 
		$a_01_11 = {00 10 41 3b c8 7c f5 68 } //02 00 
		$a_01_12 = {f9 e5 e5 e1 ab be be } //00 00 
	condition:
		any of ($a_*)
 
}