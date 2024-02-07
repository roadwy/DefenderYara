
rule Trojan_Win32_CoinMiner_MTB{
	meta:
		description = "Trojan:Win32/CoinMiner!MTB,SIGNATURE_TYPE_PEHSTR,09 00 09 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 6d 64 20 2f 63 20 74 61 73 6b 6b 69 6c 6c 20 2f 69 6d 20 74 61 73 6b 6d 67 72 2e 65 78 65 20 2f 66 20 2f 54 } //01 00  cmd /c taskkill /im taskmgr.exe /f /T
		$a_01_1 = {63 6d 64 20 2f 63 20 74 61 73 6b 6b 69 6c 6c 20 2f 69 6d 20 72 75 6e 64 6c 6c 33 32 2e 65 78 65 20 2f 66 20 2f 54 } //01 00  cmd /c taskkill /im rundll32.exe /f /T
		$a_01_2 = {63 6d 64 20 2f 63 20 74 61 73 6b 6b 69 6c 6c 20 2f 69 6d 20 61 75 74 6f 72 75 6e 73 2e 65 78 65 20 2f 66 20 2f 54 } //01 00  cmd /c taskkill /im autoruns.exe /f /T
		$a_01_3 = {63 6d 64 20 2f 63 20 74 61 73 6b 6b 69 6c 6c 20 2f 69 6d 20 70 65 72 66 6d 6f 6e 2e 65 78 65 20 2f 66 20 2f 54 } //01 00  cmd /c taskkill /im perfmon.exe /f /T
		$a_01_4 = {63 6d 64 20 2f 63 20 74 61 73 6b 6b 69 6c 6c 20 2f 69 6d 20 70 72 6f 63 65 78 70 2e 65 78 65 20 2f 66 20 2f 54 } //01 00  cmd /c taskkill /im procexp.exe /f /T
		$a_01_5 = {63 6d 64 20 2f 63 20 74 61 73 6b 6b 69 6c 6c 20 2f 69 6d 20 50 72 6f 63 65 73 73 48 61 63 6b 65 72 2e 65 78 65 20 2f 66 20 2f 54 } //05 00  cmd /c taskkill /im ProcessHacker.exe /f /T
		$a_01_6 = {58 4d 52 69 67 } //00 00  XMRig
		$a_01_7 = {00 67 16 00 00 a1 3e } //b7 00 
	condition:
		any of ($a_*)
 
}