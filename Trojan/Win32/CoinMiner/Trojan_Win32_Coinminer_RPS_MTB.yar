
rule Trojan_Win32_Coinminer_RPS_MTB{
	meta:
		description = "Trojan:Win32/Coinminer.RPS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {72 65 6e 69 6d 75 73 65 2e 6f 63 72 79 2e 63 6f 6d 2f 72 65 6e 69 6d 36 34 2e 65 78 65 } //1 renimuse.ocry.com/renim64.exe
		$a_01_1 = {74 61 73 6b 6b 69 6c 6c 20 2f 66 20 2f 69 6d 20 69 6e 74 65 6c 75 73 72 2e 65 78 65 } //1 taskkill /f /im intelusr.exe
		$a_01_2 = {70 69 6e 67 20 31 32 37 2e 30 2e 30 2e 31 20 2d 6e 20 38 } //1 ping 127.0.0.1 -n 8
		$a_01_3 = {72 73 74 2e 62 61 74 } //1 rst.bat
		$a_01_4 = {50 72 6f 63 65 73 73 48 61 63 6b 65 72 2e 65 78 65 } //1 ProcessHacker.exe
		$a_01_5 = {50 72 6f 63 6d 6f 6e 2e 65 78 65 } //1 Procmon.exe
		$a_01_6 = {72 75 73 73 69 61 6e 2e 6c 6e 67 } //1 russian.lng
		$a_01_7 = {41 6e 56 69 72 2e 65 78 65 } //1 AnVir.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}