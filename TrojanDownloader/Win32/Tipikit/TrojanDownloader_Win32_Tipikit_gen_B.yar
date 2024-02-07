
rule TrojanDownloader_Win32_Tipikit_gen_B{
	meta:
		description = "TrojanDownloader:Win32/Tipikit.gen!B,SIGNATURE_TYPE_PEHSTR_EXT,5a 00 5a 00 09 00 00 0a 00 "
		
	strings :
		$a_00_0 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //0a 00  SOFTWARE\Borland\Delphi\RTL
		$a_01_1 = {46 50 55 4d 61 73 6b 56 61 6c 75 65 } //0a 00  FPUMaskValue
		$a_00_2 = {57 72 69 74 65 46 69 6c 65 } //0a 00  WriteFile
		$a_00_3 = {43 72 65 61 74 65 46 69 6c 65 41 } //0a 00  CreateFileA
		$a_00_4 = {43 72 65 61 74 65 50 72 6f 63 65 73 73 41 } //0a 00  CreateProcessA
		$a_00_5 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //0a 00  URLDownloadToFileA
		$a_00_6 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //0a 00  SOFTWARE\Microsoft\Windows\CurrentVersion\Run
		$a_01_7 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 53 59 53 54 45 4d 33 32 4b 42 52 75 6e 4f 6e 63 65 32 2e 74 6d 5f } //0a 00  C:\WINDOWS\SYSTEM32KBRunOnce2.tm_
		$a_03_8 = {68 74 74 70 3a 2f 2f 6d 73 69 65 73 65 74 74 69 6e 67 73 2e 63 6f 6d 2f 63 68 65 63 6b 2f 90 02 10 2e 70 68 70 3f 74 73 6b 3d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}