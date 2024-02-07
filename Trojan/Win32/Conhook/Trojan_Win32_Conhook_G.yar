
rule Trojan_Win32_Conhook_G{
	meta:
		description = "Trojan:Win32/Conhook.G,SIGNATURE_TYPE_PEHSTR,70 00 70 00 0f 00 00 0a 00 "
		
	strings :
		$a_01_0 = {5c 64 77 49 6d 70 65 72 73 6f 6e 61 74 65 } //0a 00  \dwImpersonate
		$a_01_1 = {5c 64 77 41 73 79 6e 63 68 72 6f 6e 6f 75 73 } //0a 00  \dwAsynchronous
		$a_01_2 = {53 74 61 72 74 75 70 00 4e 6f 74 69 66 79 53 74 61 72 74 75 70 } //0a 00 
		$a_01_3 = {53 68 75 74 64 6f 77 6e 00 00 00 00 4e 6f 74 69 66 79 53 68 75 74 64 6f 77 6e } //0a 00 
		$a_01_4 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 57 69 6e 6c 6f 67 6f 6e 5c 4e 6f 74 69 66 79 5c } //0a 00  Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify\
		$a_01_5 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 45 78 70 6c 6f 72 65 72 5c 42 72 6f 77 73 65 72 20 48 65 6c 70 65 72 20 4f 62 6a 65 63 74 73 5c } //0a 00  SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects\
		$a_01_6 = {53 65 63 75 72 69 74 79 20 54 6f 6f 6c 62 61 72 } //0a 00  Security Toolbar
		$a_01_7 = {50 72 6f 63 65 73 73 33 32 4e 65 78 74 } //0a 00  Process32Next
		$a_01_8 = {50 72 6f 63 65 73 73 33 32 46 69 72 73 74 } //0a 00  Process32First
		$a_01_9 = {43 72 65 61 74 65 54 6f 6f 6c 68 65 6c 70 33 32 53 6e 61 70 73 68 6f 74 } //0a 00  CreateToolhelp32Snapshot
		$a_01_10 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 54 6f 6f 6c 62 61 72 } //01 00  Software\Microsoft\Internet Explorer\Toolbar
		$a_01_11 = {7b 41 39 35 42 32 38 31 36 2d 31 44 37 45 2d 34 35 36 31 2d 41 32 30 32 2d 36 38 43 30 44 45 30 32 33 35 33 41 7d } //01 00  {A95B2816-1D7E-4561-A202-68C0DE02353A}
		$a_01_12 = {7b 31 31 41 36 39 41 45 34 2d 46 42 45 44 2d 34 38 33 32 2d 41 32 42 46 2d 34 35 41 46 38 32 38 32 35 35 38 33 7d } //01 00  {11A69AE4-FBED-4832-A2BF-45AF82825583}
		$a_01_13 = {68 74 74 70 3a 2f 2f 68 74 65 70 6f 2e 63 6f 6d 2f 63 65 68 70 6d 6f 69 6e 2f 3f 63 6d 70 3d } //01 00  http://htepo.com/cehpmoin/?cmp=
		$a_01_14 = {68 74 74 70 3a 2f 2f 72 65 74 73 73 61 6d 2e 63 6f 6d 2f 68 6d 2f } //00 00  http://retssam.com/hm/
	condition:
		any of ($a_*)
 
}