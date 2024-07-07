
rule Trojan_BAT_KeyLogger_ARA_MTB{
	meta:
		description = "Trojan:BAT/KeyLogger.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 0f 00 00 "
		
	strings :
		$a_01_0 = {41 73 20 79 6f 75 20 72 65 62 6f 6f 74 2c 20 79 6f 75 20 66 69 6e 64 20 74 68 61 74 20 79 6f 75 72 20 4d 42 52 20 68 61 73 20 62 65 65 6e 20 6f 76 65 72 77 72 69 74 74 65 6e 2e } //2 As you reboot, you find that your MBR has been overwritten.
		$a_01_1 = {47 65 74 41 73 79 6e 63 4b 65 79 53 74 61 74 65 } //1 GetAsyncKeyState
		$a_80_2 = {53 70 79 54 68 65 53 70 79 } //SpyTheSpy  1
		$a_80_3 = {77 69 72 65 73 68 61 72 6b } //wireshark  1
		$a_80_4 = {53 61 6e 64 62 6f 78 69 65 20 43 6f 6e 74 72 6f 6c } //Sandboxie Control  1
		$a_80_5 = {70 72 6f 63 65 73 73 68 61 63 6b 65 72 } //processhacker  1
		$a_80_6 = {64 6e 53 70 79 } //dnSpy  1
		$a_80_7 = {56 42 6f 78 53 65 72 76 69 63 65 } //VBoxService  1
		$a_80_8 = {5c 5c 2e 5c 50 68 79 73 69 63 61 6c 44 72 69 76 65 30 } //\\.\PhysicalDrive0  1
		$a_80_9 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //Software\Microsoft\Windows\CurrentVersion\Run  1
		$a_80_10 = {70 61 73 74 65 62 69 6e 2e 63 6f 6d 2f 72 61 77 2f 3f 3f 3f } //pastebin.com/raw/???  2
		$a_80_11 = {59 6f 75 72 20 73 79 73 74 65 6d 20 69 73 20 6e 6f 77 20 6d 69 6e 65 } //Your system is now mine  2
		$a_80_12 = {53 65 6c 65 63 74 20 2a 20 46 72 6f 6d 20 41 6e 74 69 56 69 72 75 73 50 72 6f 64 75 63 74 } //Select * From AntiVirusProduct  1
		$a_80_13 = {63 6d 64 20 2f 63 20 73 74 61 72 74 20 73 68 75 74 64 6f 77 6e 20 2f 72 20 2f 66 20 2f 74 20 33 } //cmd /c start shutdown /r /f /t 3  1
		$a_80_14 = {63 6d 64 20 2f 63 20 73 63 20 64 65 6c 65 74 65 20 77 69 6e 64 65 66 65 6e 64 } //cmd /c sc delete windefend  1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1+(#a_80_8  & 1)*1+(#a_80_9  & 1)*1+(#a_80_10  & 1)*2+(#a_80_11  & 1)*2+(#a_80_12  & 1)*1+(#a_80_13  & 1)*1+(#a_80_14  & 1)*1) >=18
 
}