
rule Trojan_Win32_Coinminer_SBR_MSR{
	meta:
		description = "Trojan:Win32/Coinminer.SBR!MSR,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 63 2e 76 76 76 76 76 76 76 76 76 2e 67 61 } //1 http://c.vvvvvvvvv.ga
		$a_01_1 = {58 4d 52 69 67 20 6d 69 6e 65 72 } //1 XMRig miner
		$a_01_2 = {63 6d 64 20 2f 63 20 74 61 73 6b 6b 69 6c 6c 20 2f 66 20 2f 69 6d 20 74 61 73 6b 67 65 72 2e 65 78 65 } //1 cmd /c taskkill /f /im taskger.exe
		$a_01_3 = {63 6d 64 20 2f 63 20 74 61 73 6b 6b 69 6c 6c 20 2f 66 20 2f 69 6d 20 47 74 68 55 64 54 61 73 6b 2e 65 78 65 } //1 cmd /c taskkill /f /im GthUdTask.exe
		$a_01_4 = {63 6d 64 20 2f 63 20 74 61 73 6b 6b 69 6c 6c 20 2f 66 20 2f 69 6d 20 57 61 76 65 73 53 79 73 2e 65 78 65 } //1 cmd /c taskkill /f /im WavesSys.exe
		$a_01_5 = {63 6d 64 20 2f 63 20 74 61 73 6b 6b 69 6c 6c 20 2f 66 20 2f 69 6d 20 77 73 63 72 69 70 74 2e 65 78 65 } //1 cmd /c taskkill /f /im wscript.exe
		$a_01_6 = {63 6d 64 20 2f 63 20 74 61 73 6b 6b 69 6c 6c 20 2f 66 20 2f 69 6d 20 53 51 4c 41 47 45 4e 54 53 57 43 2e 65 78 65 } //1 cmd /c taskkill /f /im SQLAGENTSWC.exe
		$a_01_7 = {43 3a 5c 52 45 43 59 43 4c 45 52 5c 73 76 63 68 6f 73 74 6c 2e 65 78 65 } //1 C:\RECYCLER\svchostl.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}