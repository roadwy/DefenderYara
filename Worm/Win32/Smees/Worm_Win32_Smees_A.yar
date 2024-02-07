
rule Worm_Win32_Smees_A{
	meta:
		description = "Worm:Win32/Smees.A,SIGNATURE_TYPE_PEHSTR,08 00 06 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {48 65 6c 6c 6f 57 69 6e } //01 00  HelloWin
		$a_01_1 = {49 4d 57 69 6e 64 6f 77 43 6c 61 73 73 } //01 00  IMWindowClass
		$a_01_2 = {4f 4d 46 47 20 53 4f 4d 45 4f 4e 45 20 48 41 53 20 50 55 54 54 45 44 20 41 20 50 49 43 54 55 52 45 20 4f 46 20 59 4f 55 20 4f 4e 20 54 48 49 53 20 53 49 54 45 20 } //01 00  OMFG SOMEONE HAS PUTTED A PICTURE OF YOU ON THIS SITE 
		$a_01_3 = {53 54 55 50 49 44 50 49 43 54 55 52 45 53 } //01 00  STUPIDPICTURES
		$a_01_4 = {43 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 4d 53 4e 20 4d 65 73 73 65 6e 67 65 72 5c 6d 73 6e 6d 73 67 72 2e 65 78 65 } //01 00  C:\Program Files\MSN Messenger\msnmsgr.exe
		$a_01_5 = {43 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 4d 53 4e 20 4d 65 73 73 65 6e 67 65 72 5c 6d 73 72 72 2e 65 78 65 } //01 00  C:\Program Files\MSN Messenger\msrr.exe
		$a_01_6 = {4d 53 4e 48 69 64 64 65 6e 57 69 6e 64 6f 77 43 6c 61 73 73 } //01 00  MSNHiddenWindowClass
		$a_01_7 = {64 61 72 6e } //00 00  darn
	condition:
		any of ($a_*)
 
}