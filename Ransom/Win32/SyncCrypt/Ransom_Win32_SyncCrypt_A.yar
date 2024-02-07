
rule Ransom_Win32_SyncCrypt_A{
	meta:
		description = "Ransom:Win32/SyncCrypt.A,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 0d 00 00 01 00 "
		
	strings :
		$a_01_0 = {41 4d 4d 4f 55 4e 54 2e 74 78 74 } //01 00  AMMOUNT.txt
		$a_00_1 = {6d 6f 76 65 20 2f 79 20 72 65 61 64 6d 65 2e } //01 00  move /y readme.
		$a_00_2 = {63 6d 64 20 2f 63 20 6e 65 74 20 76 69 65 77 } //01 00  cmd /c net view
		$a_00_3 = {2f 73 20 2f 62 20 2f 61 2d 64 20 3e 3e } //01 00  /s /b /a-d >>
		$a_00_4 = {5c 64 65 73 6b 74 6f 70 5c 72 65 61 64 6d 65 5c } //01 00  \desktop\readme\
		$a_00_5 = {72 65 61 64 6d 65 2e 70 6e 67 22 20 26 26 20 65 78 69 74 } //01 00  readme.png" && exit
		$a_00_6 = {72 65 61 64 6d 65 2e 68 74 6d 6c 22 20 26 26 20 65 78 69 74 } //01 00  readme.html" && exit
		$a_00_7 = {73 74 61 72 74 20 74 6d 70 2e 62 61 74 } //01 00  start tmp.bat
		$a_00_8 = {69 66 20 65 78 69 73 74 20 22 73 79 6e 63 2e 65 78 65 22 20 67 6f 74 6f 20 52 65 70 65 61 74 } //02 00  if exist "sync.exe" goto Repeat
		$a_00_9 = {4d 49 49 43 49 6a 41 4e 42 67 6b 71 68 6b 69 47 39 77 30 42 41 51 45 46 41 41 4f 43 41 67 38 41 4d 49 49 43 43 67 4b 43 41 67 45 41 75 48 53 61 63 69 48 } //01 00  MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAuHSaciH
		$a_00_10 = {2e 6b 6b 00 74 6d 70 2e 62 61 74 00 } //01 00 
		$a_00_11 = {5c 42 61 63 6b 75 70 43 6c 69 65 6e 74 } //02 00  \BackupClient
		$a_03_12 = {c6 40 0a 00 e8 90 01 04 31 d2 b9 1a 00 00 00 f7 f1 8a 82 90 01 04 88 04 1e 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}