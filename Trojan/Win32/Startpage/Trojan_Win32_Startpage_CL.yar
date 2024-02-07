
rule Trojan_Win32_Startpage_CL{
	meta:
		description = "Trojan:Win32/Startpage.CL,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 0b 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 45 78 70 6c 6f 72 65 72 5c 48 69 64 65 44 65 73 6b 74 6f 70 49 63 6f 6e 73 5c 4e 65 77 53 74 61 72 74 50 61 6e 65 6c 5c 7b 38 37 31 43 35 33 38 30 2d 34 32 41 30 2d 31 30 36 39 2d 41 32 45 41 2d 30 38 30 30 32 42 33 30 33 30 39 44 7d } //01 00  Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel\{871C5380-42A0-1069-A2EA-08002B30309D}
		$a_01_1 = {53 6f 66 74 77 61 72 65 5c 50 6f 6c 69 63 69 65 73 5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 43 6f 6e 74 72 6f 6c 20 50 61 6e 65 6c 5c 53 65 63 41 64 64 53 69 74 65 73 } //01 00  Software\Policies\Microsoft\Internet Explorer\Control Panel\SecAddSites
		$a_01_2 = {53 6f 66 74 77 61 72 65 5c 50 6f 6c 69 63 69 65 73 5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 43 6f 6e 74 72 6f 6c 20 50 61 6e 65 6c 5c 48 4f 4d 45 50 41 47 45 } //01 00  Software\Policies\Microsoft\Internet Explorer\Control Panel\HOMEPAGE
		$a_01_3 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 4d 61 69 6e 5c 53 74 61 72 74 20 50 61 67 65 } //01 00  Software\Microsoft\Internet Explorer\Main\Start Page
		$a_01_4 = {75 72 6c 31 3d 68 74 74 70 3a 2f 2f 77 77 77 2e 6f 6f 6f 6f 6f 73 2e 63 6f 6d 2f } //01 00  url1=http://www.ooooos.com/
		$a_01_5 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 5c 70 69 74 } //01 00  Software\Microsoft\Windows\CurrentVersion\Run\pit
		$a_01_6 = {43 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 49 45 58 50 4c 4f 52 45 2e 45 58 45 } //01 00  C:\Program Files\Internet Explorer\IEXPLORE.EXE
		$a_01_7 = {68 74 74 70 3a 2f 2f 77 77 77 2e 78 69 61 33 2e 63 6f 6d 2f } //01 00  http://www.xia3.com/
		$a_01_8 = {5c 53 56 43 48 4f 53 54 2e 45 58 45 } //01 00  \SVCHOST.EXE
		$a_01_9 = {6b 72 6e 6c 6e 2e 66 6e 72 } //01 00  krnln.fnr
		$a_01_10 = {5c 73 65 65 70 2e 65 78 65 } //00 00  \seep.exe
	condition:
		any of ($a_*)
 
}