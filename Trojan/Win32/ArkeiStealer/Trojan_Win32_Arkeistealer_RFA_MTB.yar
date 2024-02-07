
rule Trojan_Win32_Arkeistealer_RFA_MTB{
	meta:
		description = "Trojan:Win32/Arkeistealer.RFA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 0b 00 00 01 00 "
		
	strings :
		$a_01_0 = {2a 77 61 6c 6c 65 74 2a 2e 64 61 74 } //01 00  *wallet*.dat
		$a_01_1 = {5c 66 69 6c 65 73 5c 57 61 6c 6c 65 74 73 } //01 00  \files\Wallets
		$a_01_2 = {5c 45 6c 65 63 74 72 75 6d 2d 4c 54 43 5c 77 61 6c 6c 65 74 73 5c } //01 00  \Electrum-LTC\wallets\
		$a_01_3 = {5c 45 6c 65 63 74 72 6f 6e 43 61 73 68 5c 77 61 6c 6c 65 74 73 5c } //01 00  \ElectronCash\wallets\
		$a_01_4 = {43 72 65 61 74 65 54 6f 6f 6c 68 65 6c 70 33 32 53 6e 61 70 73 68 6f 74 } //01 00  CreateToolhelp32Snapshot
		$a_01_5 = {47 65 74 53 79 73 74 65 6d 49 6e 66 6f } //01 00  GetSystemInfo
		$a_01_6 = {5c 47 6f 6f 67 6c 65 5c 43 68 72 6f 6d 65 5c 55 73 65 72 20 44 61 74 61 5c } //01 00  \Google\Chrome\User Data\
		$a_01_7 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //01 00  IsDebuggerPresent
		$a_01_8 = {47 65 74 53 74 61 72 74 75 70 49 6e 66 6f 57 } //01 00  GetStartupInfoW
		$a_01_9 = {43 50 55 20 43 6f 75 6e 74 3a 20 } //01 00  CPU Count: 
		$a_01_10 = {47 65 74 4b 65 79 62 6f 61 72 64 4c 61 79 6f 75 74 4c 69 73 74 } //00 00  GetKeyboardLayoutList
	condition:
		any of ($a_*)
 
}