
rule Trojan_Win32_RedLineStealer_MVA_MTB{
	meta:
		description = "Trojan:Win32/RedLineStealer.MVA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {2e 75 30 6d 63 30 44 63 } //01 00  .u0mc0Dc
		$a_01_1 = {62 6c 61 63 6b 6c 69 73 74 65 64 20 6b 65 79 } //01 00  blacklisted key
		$a_01_2 = {45 6e 63 72 79 70 74 69 6f 6e 20 63 6f 6e 73 74 61 6e 74 73 } //01 00  Encryption constants
		$a_01_3 = {65 6e 63 72 79 70 74 69 6f 6e 20 73 65 63 74 69 6f 6e 28 73 29 20 6d 69 67 68 74 20 6e 6f 74 20 62 65 20 70 72 6f 70 65 72 6c 79 20 64 65 63 72 79 70 74 65 64 } //01 00  encryption section(s) might not be properly decrypted
		$a_01_4 = {45 00 6e 00 74 00 65 00 72 00 20 00 4d 00 6f 00 64 00 65 00 20 00 50 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00 } //01 00  Enter Mode Password
		$a_01_5 = {5c 00 54 00 45 00 4d 00 50 00 5c 00 61 00 73 00 70 00 72 00 5f 00 6b 00 65 00 79 00 73 00 2e 00 69 00 6e 00 69 00 } //01 00  \TEMP\aspr_keys.ini
		$a_01_6 = {47 65 74 4b 65 79 62 6f 61 72 64 54 79 70 65 } //01 00  GetKeyboardType
		$a_01_7 = {47 65 74 41 73 79 6e 63 4b 65 79 53 74 61 74 65 } //00 00  GetAsyncKeyState
	condition:
		any of ($a_*)
 
}