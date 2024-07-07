
rule Trojan_Win32_Helpud_BA_dll{
	meta:
		description = "Trojan:Win32/Helpud.BA!dll,SIGNATURE_TYPE_PEHSTR,04 00 04 00 06 00 00 "
		
	strings :
		$a_01_0 = {48 6f 6f 6b 2e 64 6c 6c 00 6d 6b 73 48 6f 6f 6b 00 6d 74 7a 48 6f 6f 6b 00 } //3
		$a_01_1 = {55 73 65 72 2d 41 67 65 6e 74 3a 20 49 6e 74 72 65 6e 65 74 20 45 78 70 6c 6f 72 65 72 } //1 User-Agent: Intrenet Explorer
		$a_01_2 = {72 6f 6c 65 76 69 65 77 2e 64 6c 6c } //1 roleview.dll
		$a_01_3 = {73 6f 75 6c 2e 65 78 65 } //1 soul.exe
		$a_01_4 = {23 33 32 37 37 30 00 00 58 50 31 00 42 75 74 74 6f 6e 00 } //1
		$a_01_5 = {2d 39 35 33 46 2d 34 43 43 38 2d 42 36 38 46 2d 44 33 34 39 46 46 34 31 44 36 37 37 7d } //1 -953F-4CC8-B68F-D349FF41D677}
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=4
 
}