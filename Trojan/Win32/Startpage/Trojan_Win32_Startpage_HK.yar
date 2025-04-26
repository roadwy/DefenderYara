
rule Trojan_Win32_Startpage_HK{
	meta:
		description = "Trojan:Win32/Startpage.HK,SIGNATURE_TYPE_PEHSTR,04 00 04 00 0a 00 00 "
		
	strings :
		$a_01_0 = {5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 4e 69 6b 6f 5c 49 45 58 50 4c 4f 52 45 2e 45 58 45 } //1 \Internet Explorer\Niko\IEXPLORE.EXE
		$a_01_1 = {5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 69 65 78 70 6c 6f 72 65 2e 65 78 65 20 25 31 20 68 25 74 25 74 25 70 25 3a 25 2f 25 2f } //1 \Internet Explorer\iexplore.exe %1 h%t%t%p%:%/%/
		$a_01_2 = {44 65 66 61 75 6c 74 73 5c 77 69 6e 73 68 75 74 64 6f 77 6e 2e 76 62 73 } //1 Defaults\winshutdown.vbs
		$a_01_3 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //1 SOFTWARE\Microsoft\Windows\CurrentVersion\Run
		$a_01_4 = {3f 74 6e 3d 6c 65 69 7a 68 65 6e } //1 ?tn=leizhen
		$a_01_5 = {64 65 73 6b 6d 61 74 65 2e 6e 6c 73 } //1 deskmate.nls
		$a_01_6 = {72 65 67 20 61 64 64 20 48 4b 43 55 5c 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 50 6f 6c 69 63 69 65 73 5c 41 73 73 6f 63 69 61 74 69 6f 6e 73 20 2f 76 20 4d 6f 64 52 69 73 6b 46 69 6c 65 54 79 70 65 73 } //1 reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Associations /v ModRiskFileTypes
		$a_01_7 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 41 64 76 61 6e 63 65 64 20 49 4e 46 20 53 65 74 75 70 } //1 SOFTWARE\Microsoft\Advanced INF Setup
		$a_01_8 = {67 70 75 70 64 61 74 65 20 2f 66 6f 72 63 65 } //1 gpupdate /force
		$a_01_9 = {53 4f 46 54 57 41 52 45 5c 4b 69 6e 67 73 61 66 74 } //1 SOFTWARE\Kingsaft
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1) >=4
 
}