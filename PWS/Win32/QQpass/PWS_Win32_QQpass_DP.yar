
rule PWS_Win32_QQpass_DP{
	meta:
		description = "PWS:Win32/QQpass.DP,SIGNATURE_TYPE_PEHSTR_EXT,34 00 34 00 08 00 00 "
		
	strings :
		$a_00_0 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 77 69 6e 64 6f 77 73 5c 63 75 72 72 65 6e 74 76 65 72 73 69 6f 6e 5c 72 75 6e } //10 SOFTWARE\Microsoft\windows\currentversion\run
		$a_00_1 = {5c 77 69 6e 73 74 61 72 74 65 72 2e 65 78 65 } //10 \winstarter.exe
		$a_02_2 = {68 74 74 70 3a 2f 2f [0-20] 2e 61 73 70 } //10
		$a_00_3 = {26 50 61 73 73 77 6f 72 64 3d } //10 &Password=
		$a_00_4 = {54 65 6e 63 65 6e 74 5f 51 51 42 61 72 } //10 Tencent_QQBar
		$a_00_5 = {5c 6e 65 77 75 6d 73 67 2e 65 78 65 } //1 \newumsg.exe
		$a_00_6 = {5c 61 75 74 6f 72 75 6e 2e 69 6e 66 } //1 \autorun.inf
		$a_00_7 = {5c 73 79 73 61 75 74 6f 72 75 6e 2e 69 6e 66 } //1 \sysautorun.inf
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*10+(#a_02_2  & 1)*10+(#a_00_3  & 1)*10+(#a_00_4  & 1)*10+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1) >=52
 
}