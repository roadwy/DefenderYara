
rule Trojan_BAT_CoinMiner_PA13_MTB{
	meta:
		description = "Trojan:BAT/CoinMiner.PA13!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 0e 00 00 "
		
	strings :
		$a_80_0 = {2d 2d 75 72 6c 20 70 6f 6f 6c 2e 68 61 73 68 76 61 75 6c 74 2e 70 72 6f 3a 38 30 } //--url pool.hashvault.pro:80  1
		$a_80_1 = {2d 2d 70 61 73 73 20 58 4d 52 20 2d 2d 64 6f 6e 61 74 65 2d 6c 65 76 65 6c 20 31 20 2d 2d 74 6c 73 20 2d 2d 74 6c 73 2d 66 69 6e 67 65 72 70 72 69 6e 74 } //--pass XMR --donate-level 1 --tls --tls-fingerprint  1
		$a_80_2 = {74 6c 6d 61 6e 61 } //tlmana  1
		$a_80_3 = {43 6f 6e 73 65 6e 74 50 72 6f 6d 70 74 42 65 68 61 76 69 6f 72 41 64 6d 69 6e } //ConsentPromptBehaviorAdmin  1
		$a_80_4 = {50 72 6f 6d 70 74 4f 6e 53 65 63 75 72 65 44 65 73 6b 74 6f 70 } //PromptOnSecureDesktop  1
		$a_80_5 = {6b 69 6c 6c } //kill  1
		$a_80_6 = {41 64 64 2d 4d 70 50 72 65 66 65 72 65 6e 63 65 20 2d 45 78 63 6c 75 73 69 6f 6e 50 61 74 68 } //Add-MpPreference -ExclusionPath  1
		$a_80_7 = {53 6f 66 74 77 61 72 65 5c 43 6c 61 73 73 65 73 5c 6d 73 63 66 69 6c 65 5c 53 68 65 6c 6c 5c 4f 70 65 6e 5c 63 6f 6d 6d 61 6e 64 } //Software\Classes\mscfile\Shell\Open\command  1
		$a_80_8 = {6d 69 6e 65 72 2e 65 78 65 } //miner.exe  1
		$a_80_9 = {50 72 6f 63 65 73 73 48 61 63 6b 65 72 } //ProcessHacker  1
		$a_80_10 = {4f 70 65 6e 48 61 72 64 77 61 72 65 4d 6f 6e 69 74 6f 72 } //OpenHardwareMonitor  1
		$a_80_11 = {4e 75 6d 62 65 72 4f 66 4c 6f 67 69 63 61 6c 50 72 6f 63 65 73 73 6f 72 73 } //NumberOfLogicalProcessors  1
		$a_80_12 = {53 45 4c 45 43 54 20 2a 20 46 52 4f 4d 20 57 69 6e 33 32 5f 56 69 64 65 6f 43 6f 6e 74 72 6f 6c 6c 65 72 } //SELECT * FROM Win32_VideoController  1
		$a_80_13 = {73 63 68 74 61 73 6b 73 2e 65 78 65 20 2f 63 72 65 61 74 65 20 2f 66 20 2f 73 63 20 4d 49 4e 55 54 45 } //schtasks.exe /create /f /sc MINUTE  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1+(#a_80_8  & 1)*1+(#a_80_9  & 1)*1+(#a_80_10  & 1)*1+(#a_80_11  & 1)*1+(#a_80_12  & 1)*1+(#a_80_13  & 1)*1) >=14
 
}