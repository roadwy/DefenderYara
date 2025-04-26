
rule Trojan_Win32_Khalesi_ARA_MTB{
	meta:
		description = "Trojan:Win32/Khalesi.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,11 00 11 00 10 00 00 "
		
	strings :
		$a_01_0 = {6f 6c 6c 79 64 62 67 2e 65 78 65 } //1 ollydbg.exe
		$a_01_1 = {70 72 6f 63 6d 6f 6e 2e 65 78 65 } //1 procmon.exe
		$a_01_2 = {49 6d 6d 75 6e 69 74 79 44 65 62 75 67 67 65 72 2e 65 78 65 } //1 ImmunityDebugger.exe
		$a_01_3 = {73 6e 69 66 66 5f 68 69 74 2e 65 78 65 } //1 sniff_hit.exe
		$a_01_4 = {77 69 6e 64 62 67 2e 65 78 65 } //1 windbg.exe
		$a_01_5 = {6a 6f 65 62 6f 78 63 6f 6e 74 72 6f 6c 2e 65 78 65 } //1 joeboxcontrol.exe
		$a_01_6 = {56 6d 77 61 72 65 74 72 61 74 2e 65 78 65 } //1 Vmwaretrat.exe
		$a_01_7 = {76 62 6f 78 73 65 72 76 69 63 65 2e 65 78 65 } //1 vboxservice.exe
		$a_01_8 = {74 61 73 6b 6b 69 6c 6c 20 2f 46 49 20 22 49 4d 41 47 45 4e 41 4d 45 20 65 71 20 63 68 65 61 74 65 6e 67 69 6e 65 2a 22 20 2f 49 4d 20 2a 20 2f 46 20 2f 54 20 3e 6e 75 6c 20 32 3e 26 31 } //1 taskkill /FI "IMAGENAME eq cheatengine*" /IM * /F /T >nul 2>&1
		$a_01_9 = {74 61 73 6b 6b 69 6c 6c 20 2f 46 49 20 22 49 4d 41 47 45 4e 41 4d 45 20 65 71 20 68 74 74 70 64 65 62 75 67 67 65 72 2a 22 20 2f 49 4d 20 2a 20 2f 46 20 2f 54 20 3e 6e 75 6c 20 32 3e 26 31 } //1 taskkill /FI "IMAGENAME eq httpdebugger*" /IM * /F /T >nul 2>&1
		$a_01_10 = {74 61 73 6b 6b 69 6c 6c 20 2f 46 49 20 22 49 4d 41 47 45 4e 41 4d 45 20 65 71 20 70 72 6f 63 65 73 73 68 61 63 6b 65 72 2a 22 20 2f 49 4d 20 2a 20 2f 46 20 2f 54 20 3e 6e 75 6c 20 32 3e 26 31 } //1 taskkill /FI "IMAGENAME eq processhacker*" /IM * /F /T >nul 2>&1
		$a_01_11 = {74 61 73 6b 6b 69 6c 6c 20 2f 46 49 20 22 49 4d 41 47 45 4e 41 4d 45 20 65 71 20 66 69 64 64 6c 65 72 2a 22 20 2f 49 4d 20 2a 20 2f 46 20 2f 54 20 3e 6e 75 6c 20 32 3e 26 31 } //1 taskkill /FI "IMAGENAME eq fiddler*" /IM * /F /T >nul 2>&1
		$a_01_12 = {74 61 73 6b 6b 69 6c 6c 20 2f 46 49 20 22 49 4d 41 47 45 4e 41 4d 45 20 65 71 20 77 69 72 65 73 68 61 72 6b 2a 22 20 2f 49 4d 20 2a 20 2f 46 20 2f 54 20 3e 6e 75 6c 20 32 3e 26 31 } //1 taskkill /FI "IMAGENAME eq wireshark*" /IM * /F /T >nul 2>&1
		$a_01_13 = {74 61 73 6b 6b 69 6c 6c 20 2f 46 49 20 22 49 4d 41 47 45 4e 41 4d 45 20 65 71 20 69 64 61 2a 22 20 2f 49 4d 20 2a 20 2f 46 20 2f 54 20 3e 6e 75 6c 20 32 3e 26 31 } //1 taskkill /FI "IMAGENAME eq ida*" /IM * /F /T >nul 2>&1
		$a_01_14 = {73 63 20 73 74 6f 70 20 6e 70 66 20 3e 6e 75 6c 20 32 3e 26 31 } //1 sc stop npf >nul 2>&1
		$a_01_15 = {64 69 73 63 6f 72 64 2e 67 67 2f 64 36 52 47 4d 4b 43 72 6a 36 } //2 discord.gg/d6RGMKCrj6
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_01_13  & 1)*1+(#a_01_14  & 1)*1+(#a_01_15  & 1)*2) >=17
 
}