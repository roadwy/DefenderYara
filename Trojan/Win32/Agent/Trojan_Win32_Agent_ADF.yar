
rule Trojan_Win32_Agent_ADF{
	meta:
		description = "Trojan:Win32/Agent.ADF,SIGNATURE_TYPE_PEHSTR_EXT,ffffffe7 00 ffffffe6 00 08 00 00 "
		
	strings :
		$a_02_0 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 53 59 53 54 45 4d 33 32 5c [0-09] 2e 65 78 65 } //100
		$a_00_1 = {77 77 77 2e 70 6f 72 6e 2e 63 6f 6d } //100 www.porn.com
		$a_00_2 = {53 68 65 6c 6c 45 78 65 63 75 74 65 } //10 ShellExecute
		$a_00_3 = {42 6c 6f 63 6b 49 6e 70 75 74 } //10 BlockInput
		$a_00_4 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //10 Software\Microsoft\Windows\CurrentVersion\Run
		$a_00_5 = {4e 65 61 6e 64 65 72 74 68 61 6c 20 69 73 20 77 61 74 63 68 69 6e 67 20 79 6f 75 } //1 Neanderthal is watching you
		$a_00_6 = {59 6f 75 20 63 61 6e 27 74 20 63 61 6e 63 65 6c 20 6d 65 20 6d 6f 74 68 65 72 20 66 75 63 6b 65 72 21 } //1 You can't cancel me mother fucker!
		$a_00_7 = {4e 61 75 67 68 74 79 2c 20 4e 61 75 67 68 74 79 2c 20 6c 6f 6f 6b 69 6e 67 20 61 74 20 70 6f 72 6e 20 61 72 65 20 77 65 20 6e 6f 77 3f 2e 2e 2e 20 44 69 73 70 69 63 61 62 6c 65 } //1 Naughty, Naughty, looking at porn are we now?... Dispicable
	condition:
		((#a_02_0  & 1)*100+(#a_00_1  & 1)*100+(#a_00_2  & 1)*10+(#a_00_3  & 1)*10+(#a_00_4  & 1)*10+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1) >=230
 
}
rule Trojan_Win32_Agent_ADF_2{
	meta:
		description = "Trojan:Win32/Agent.ADF,SIGNATURE_TYPE_PEHSTR,0f 00 0d 00 19 00 00 "
		
	strings :
		$a_01_0 = {25 73 79 73 74 65 6d 25 5c 64 65 62 69 74 6f 73 2e 73 63 72 } //1 %system%\debitos.scr
		$a_01_1 = {25 73 79 73 74 65 6d 25 5c 6d 79 5f 62 61 63 6b 64 6f 6f 72 20 28 6e 6f 20 78 20 77 69 6e 20 32 30 30 30 29 2e 65 78 65 } //1 %system%\my_backdoor (no x win 2000).exe
		$a_01_2 = {25 73 79 73 74 65 6d 25 5c 65 65 78 70 6c 6f 72 65 72 2e 65 78 65 } //1 %system%\eexplorer.exe
		$a_01_3 = {25 73 79 73 74 65 6d 25 5c 6b 65 79 68 6f 6f 6b 2e 64 6c 6c } //1 %system%\keyhook.dll
		$a_01_4 = {25 77 69 6e 64 69 72 25 5c 68 65 6c 70 5c 6b 69 6c 6c 2e 65 78 65 } //1 %windir%\help\kill.exe
		$a_01_5 = {25 64 65 73 6b 74 6f 70 25 5c 42 61 63 6b 64 6f 6f 72 2e 49 52 43 2e 43 6c 6f 6e 65 72 2e 76 2e 65 78 65 } //1 %desktop%\Backdoor.IRC.Cloner.v.exe
		$a_01_6 = {25 64 65 73 6b 74 6f 70 25 5c 42 61 63 6b 64 6f 6f 72 2e 49 52 43 2e 42 6e 63 2e 63 2e 65 78 65 } //1 %desktop%\Backdoor.IRC.Bnc.c.exe
		$a_01_7 = {25 64 65 73 6b 74 6f 70 25 5c 42 61 63 6b 64 6f 6f 72 2e 49 52 43 2e 42 65 6c 69 6f 2e 65 78 65 } //1 %desktop%\Backdoor.IRC.Belio.exe
		$a_01_8 = {25 64 65 73 6b 74 6f 70 25 5c 42 61 63 6b 64 6f 6f 72 2e 49 52 43 2e 42 61 6e 6e 65 64 2e 62 2e 65 78 65 } //1 %desktop%\Backdoor.IRC.Banned.b.exe
		$a_01_9 = {25 64 65 73 6b 74 6f 70 25 5c 42 61 63 6b 64 6f 6f 72 2e 49 52 43 2e 41 74 61 6b 61 2e 61 2e 65 78 65 } //1 %desktop%\Backdoor.IRC.Ataka.a.exe
		$a_01_10 = {25 73 79 73 74 65 6d 25 5c 73 76 63 78 6e 76 33 32 2e 65 78 65 } //1 %system%\svcxnv32.exe
		$a_01_11 = {25 77 69 6e 64 69 72 25 5c 77 69 6e 73 6f 63 6b 73 35 2e 65 78 65 } //1 %windir%\winsocks5.exe
		$a_01_12 = {25 73 79 73 74 65 6d 25 5c 77 69 6e 73 64 61 74 61 2e 65 78 65 } //1 %system%\winsdata.exe
		$a_01_13 = {25 73 79 73 74 65 6d 25 5c 72 61 76 6d 6f 6e 64 2e 65 78 65 } //1 %system%\ravmond.exe
		$a_01_14 = {25 73 79 73 74 65 6d 25 5c 57 49 4e 57 47 50 58 2e 45 58 45 } //1 %system%\WINWGPX.EXE
		$a_01_15 = {25 64 65 73 6b 74 6f 70 25 5c 42 61 63 6b 64 6f 6f 72 2e 49 52 43 2e 41 63 6e 75 7a 2e 65 78 65 } //1 %desktop%\Backdoor.IRC.Acnuz.exe
		$a_01_16 = {25 64 65 73 6b 74 6f 70 25 5c 42 61 63 6b 64 6f 6f 72 2e 41 53 50 2e 41 63 65 2e 62 2e 65 78 65 } //1 %desktop%\Backdoor.ASP.Ace.b.exe
		$a_01_17 = {25 64 65 73 6b 74 6f 70 25 5c 42 61 63 6b 64 6f 6f 72 2e 41 53 50 2e 41 63 65 2e 61 2e 65 78 65 } //1 %desktop%\Backdoor.ASP.Ace.a.exe
		$a_01_18 = {25 64 65 73 6b 74 6f 70 25 5c 6d 73 6e 5c 42 61 63 6b 64 6f 6f 72 2e 57 69 6e 33 32 2e 4d 53 4e 43 6f 72 72 75 70 74 2e 65 78 65 2e 65 78 65 } //1 %desktop%\msn\Backdoor.Win32.MSNCorrupt.exe.exe
		$a_01_19 = {25 64 65 73 6b 74 6f 70 25 5c 42 61 63 6b 64 6f 6f 72 2e 57 69 6e 33 32 2e 42 69 66 72 6f 73 65 2e 61 2e 65 78 65 } //1 %desktop%\Backdoor.Win32.Bifrose.a.exe
		$a_01_20 = {25 64 65 73 6b 74 6f 70 25 5c 41 75 74 6f 2d 4b 65 79 6c 6f 67 67 65 72 2d 53 65 74 75 70 2e 65 78 65 } //1 %desktop%\Auto-Keylogger-Setup.exe
		$a_01_21 = {25 64 65 73 6b 74 6f 70 25 5c 41 75 72 6f 72 61 49 6e 66 65 63 74 69 6f 6e 2e 65 78 65 } //1 %desktop%\AuroraInfection.exe
		$a_01_22 = {73 6f 66 74 77 61 72 65 5c 61 6e 74 69 2d 6c 61 6d 65 72 20 62 61 63 6b 64 6f 6f 72 } //1 software\anti-lamer backdoor
		$a_01_23 = {6d 79 5f 62 61 63 6b 64 6f 6f 72 20 28 6e 6f 20 78 20 77 69 6e 20 32 30 30 30 29 } //1 my_backdoor (no x win 2000)
		$a_01_24 = {25 77 69 6e 64 69 72 25 69 6e 74 65 72 6e 61 74 2e 65 78 65 } //1 %windir%internat.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_01_13  & 1)*1+(#a_01_14  & 1)*1+(#a_01_15  & 1)*1+(#a_01_16  & 1)*1+(#a_01_17  & 1)*1+(#a_01_18  & 1)*1+(#a_01_19  & 1)*1+(#a_01_20  & 1)*1+(#a_01_21  & 1)*1+(#a_01_22  & 1)*1+(#a_01_23  & 1)*1+(#a_01_24  & 1)*1) >=13
 
}