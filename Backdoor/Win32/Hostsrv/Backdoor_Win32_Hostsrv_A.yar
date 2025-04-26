
rule Backdoor_Win32_Hostsrv_A{
	meta:
		description = "Backdoor:Win32/Hostsrv.A,SIGNATURE_TYPE_PEHSTR,05 00 05 00 06 00 00 "
		
	strings :
		$a_01_0 = {25 57 49 4e 44 49 52 25 5c 73 79 73 74 65 6d 33 32 5c 64 72 69 76 65 72 73 5c 65 74 63 5c 68 6f 73 74 73 } //1 %WINDIR%\system32\drivers\etc\hosts
		$a_01_1 = {55 73 61 67 65 3a 20 73 72 76 33 32 2e 65 78 65 20 2d 5b 73 74 61 72 74 7c 73 74 6f 70 7c 69 6e 73 74 61 6c 6c 7c 75 6e 69 6e 73 } //2 Usage: srv32.exe -[start|stop|install|unins
		$a_01_2 = {53 65 72 76 65 72 3a 20 46 75 63 6b 59 6f 75 } //1 Server: FuckYou
		$a_01_3 = {74 61 73 6b 6b 69 6c 6c 20 2f 66 20 2f 69 6d } //1 taskkill /f /im
		$a_01_4 = {69 70 63 6f 6e 66 69 67 20 2f 66 6c 75 73 68 64 6e 73 } //1 ipconfig /flushdns
		$a_01_5 = {74 00 61 00 73 00 6b 00 6d 00 67 00 72 00 2e 00 65 00 78 00 65 00 2c 00 72 00 65 00 67 00 65 00 64 00 69 00 74 00 2e 00 65 00 78 00 65 00 2c 00 72 00 73 00 74 00 72 00 75 00 69 00 2e 00 65 00 78 00 65 00 2c 00 6d 00 73 00 63 00 6f 00 6e 00 66 00 69 00 67 00 2e 00 65 00 78 00 65 00 2c 00 61 00 76 00 7a 00 2e 00 65 00 78 00 65 00 } //1 taskmgr.exe,regedit.exe,rstrui.exe,msconfig.exe,avz.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=5
 
}