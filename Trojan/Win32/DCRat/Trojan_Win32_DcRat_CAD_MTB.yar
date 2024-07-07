
rule Trojan_Win32_DcRat_CAD_MTB{
	meta:
		description = "Trojan:Win32/DcRat.CAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {63 6d 64 2e 65 78 65 20 2f 63 20 70 6f 77 65 72 73 68 65 6c 6c 20 2d 43 6f 6d 6d 61 6e 64 20 41 64 64 2d 4d 70 50 72 65 66 65 72 65 6e 63 65 20 2d 45 78 63 6c 75 73 69 6f 6e 50 61 74 68 20 22 43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 } //1 cmd.exe /c powershell -Command Add-MpPreference -ExclusionPath "C:\Users\Public
		$a_01_1 = {63 6d 64 2e 65 78 65 20 2f 63 20 70 6f 77 65 72 73 68 65 6c 6c 20 2d 43 6f 6d 6d 61 6e 64 20 41 64 64 2d 4d 70 50 72 65 66 65 72 65 6e 63 65 20 2d 45 78 63 6c 75 73 69 6f 6e 50 72 6f 63 65 73 73 20 22 43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 72 65 61 64 6d 65 2e 65 78 65 } //1 cmd.exe /c powershell -Command Add-MpPreference -ExclusionProcess "C:\Users\Public\readme.exe
		$a_01_2 = {63 6d 64 2e 65 78 65 20 2f 63 20 70 6f 77 65 72 73 68 65 6c 6c 20 22 43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 72 65 61 64 6d 65 2e 65 78 65 } //1 cmd.exe /c powershell "C:\Users\Public\readme.exe
		$a_01_3 = {53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 52 00 75 00 6e 00 } //1 Software\Microsoft\Windows\CurrentVersion\Run
		$a_01_4 = {53 00 79 00 73 00 74 00 65 00 6d 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 43 00 6f 00 6e 00 74 00 72 00 6f 00 6c 00 53 00 65 00 74 00 5c 00 43 00 6f 00 6e 00 74 00 72 00 6f 00 6c 00 5c 00 4b 00 65 00 79 00 62 00 6f 00 61 00 72 00 64 00 20 00 4c 00 61 00 79 00 6f 00 75 00 74 00 73 00 5c 00 25 00 2e 00 38 00 78 00 } //1 System\CurrentControlSet\Control\Keyboard Layouts\%.8x
		$a_01_5 = {41 6e 79 44 65 73 6b } //1 AnyDesk
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}