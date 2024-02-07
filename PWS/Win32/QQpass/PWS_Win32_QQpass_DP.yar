
rule PWS_Win32_QQpass_DP{
	meta:
		description = "PWS:Win32/QQpass.DP,SIGNATURE_TYPE_PEHSTR_EXT,34 00 34 00 08 00 00 0a 00 "
		
	strings :
		$a_00_0 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 77 69 6e 64 6f 77 73 5c 63 75 72 72 65 6e 74 76 65 72 73 69 6f 6e 5c 72 75 6e } //0a 00  SOFTWARE\Microsoft\windows\currentversion\run
		$a_00_1 = {5c 77 69 6e 73 74 61 72 74 65 72 2e 65 78 65 } //0a 00  \winstarter.exe
		$a_02_2 = {68 74 74 70 3a 2f 2f 90 02 20 2e 61 73 70 90 00 } //0a 00 
		$a_00_3 = {26 50 61 73 73 77 6f 72 64 3d } //0a 00  &Password=
		$a_00_4 = {54 65 6e 63 65 6e 74 5f 51 51 42 61 72 } //01 00  Tencent_QQBar
		$a_00_5 = {5c 6e 65 77 75 6d 73 67 2e 65 78 65 } //01 00  \newumsg.exe
		$a_00_6 = {5c 61 75 74 6f 72 75 6e 2e 69 6e 66 } //01 00  \autorun.inf
		$a_00_7 = {5c 73 79 73 61 75 74 6f 72 75 6e 2e 69 6e 66 } //00 00  \sysautorun.inf
	condition:
		any of ($a_*)
 
}