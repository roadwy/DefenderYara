
rule Trojan_Win32_Killav_HG{
	meta:
		description = "Trojan:Win32/Killav.HG,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {74 61 73 6b 6b 69 6c 6c 20 2f 66 20 2f 74 20 2f 69 6d 20 4d 53 41 53 43 75 69 2e 65 78 65 } //1 taskkill /f /t /im MSASCui.exe
		$a_01_1 = {6e 65 74 20 73 74 6f 70 20 57 69 6e 44 65 66 65 6e 64 } //1 net stop WinDefend
		$a_01_2 = {73 63 20 63 6f 6e 66 69 67 20 77 75 61 75 73 65 72 76 20 73 74 61 72 74 3d 20 64 69 73 61 62 6c 65 64 } //1 sc config wuauserv start= disabled
		$a_01_3 = {5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 20 00 44 00 65 00 66 00 65 00 6e 00 64 00 65 00 72 00 5c 00 73 00 65 00 63 00 75 00 72 00 69 00 74 00 79 00 2e 00 62 00 61 00 74 00 } //1 \Windows Defender\security.bat
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}