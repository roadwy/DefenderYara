
rule TrojanDownloader_Win32_Zlob_KJ{
	meta:
		description = "TrojanDownloader:Win32/Zlob.KJ,SIGNATURE_TYPE_PEHSTR_EXT,24 00 23 00 0b 00 00 05 00 "
		
	strings :
		$a_01_0 = {53 6f 66 74 77 61 72 65 5c 57 65 62 20 54 65 63 68 6e 6f 6c 6f 67 69 65 73 } //05 00  Software\Web Technologies
		$a_01_1 = {73 74 65 72 65 6f 00 } //02 00 
		$a_01_2 = {61 77 65 72 25 64 2e 62 61 74 } //02 00  awer%d.bat
		$a_01_3 = {25 73 5c 7a 66 25 73 25 64 2e 65 78 65 } //01 00  %s\zf%s%d.exe
		$a_01_4 = {69 66 20 65 78 69 73 74 20 22 25 73 22 20 67 6f 74 6f 20 52 65 70 65 61 74 } //01 00  if exist "%s" goto Repeat
		$a_01_5 = {72 6d 64 69 72 20 22 25 73 22 } //01 00  rmdir "%s"
		$a_01_6 = {64 65 6c 20 22 25 73 22 } //05 00  del "%s"
		$a_01_7 = {7b 36 42 46 35 32 41 35 32 } //05 00  {6BF52A52
		$a_01_8 = {48 74 74 70 53 65 6e 64 52 65 71 75 65 73 74 41 } //05 00  HttpSendRequestA
		$a_01_9 = {53 68 65 6c 6c 45 78 65 63 75 74 65 41 } //05 00  ShellExecuteA
		$a_01_10 = {57 72 69 74 65 46 69 6c 65 } //00 00  WriteFile
	condition:
		any of ($a_*)
 
}