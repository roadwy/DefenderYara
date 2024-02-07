
rule Trojan_Win32_Ifrasif_A{
	meta:
		description = "Trojan:Win32/Ifrasif.A,SIGNATURE_TYPE_PEHSTR,22 00 20 00 07 00 00 0a 00 "
		
	strings :
		$a_01_0 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 73 79 73 74 65 6d 33 32 5c 72 65 67 2e 65 78 65 20 64 65 6c 65 74 65 20 48 4b 45 59 5f 4c 4f 43 41 4c 5f 4d 41 43 48 49 4e 45 5c 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 20 2f 76 20 6d 73 73 79 73 69 66 20 2f 66 } //0a 00  C:\WINDOWS\system32\reg.exe delete HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run /v mssysif /f
		$a_01_1 = {72 65 67 2e 65 78 65 20 61 64 64 20 48 4b 45 59 5f 4c 4f 43 41 4c 5f 4d 41 43 48 49 4e 45 5c 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 20 2f 74 20 52 45 47 5f 53 5a } //0a 00  reg.exe add HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run /t REG_SZ
		$a_01_2 = {77 69 6e 64 6f 77 2e 73 74 61 74 75 73 3d 27 44 6f 6e 65 27 3b 64 6f 63 75 6d 65 6e 74 2e 77 72 69 74 65 28 27 3c 69 66 72 61 6d 65 20 20 69 64 3d } //01 00  window.status='Done';document.write('<iframe  id=
		$a_01_3 = {49 66 66 72 61 6d 65 72 20 74 68 72 65 61 64 20 73 74 6f 70 } //01 00  Ifframer thread stop
		$a_01_4 = {3c 73 63 72 69 70 74 3e 66 75 6e 63 74 69 6f 6e 20 76 28 2e 2a 29 31 37 39 33 41 36 45 36 46 36 45 36 35 32 37 33 45 33 43 32 46 36 39 36 36 37 32 36 31 36 44 36 35 33 45 } //01 00  <script>function v(.*)1793A6E6F6E65273E3C2F696672616D653E
		$a_01_5 = {46 74 70 47 65 74 46 69 6c 65 41 } //01 00  FtpGetFileA
		$a_01_6 = {49 6e 74 65 72 6e 65 74 46 69 6e 64 4e 65 78 74 46 69 6c 65 41 } //00 00  InternetFindNextFileA
	condition:
		any of ($a_*)
 
}