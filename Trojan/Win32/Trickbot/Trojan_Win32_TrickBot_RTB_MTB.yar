
rule Trojan_Win32_TrickBot_RTB_MTB{
	meta:
		description = "Trojan:Win32/TrickBot.RTB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 74 75 70 20 77 69 6e 64 6f 77 73 20 64 65 66 65 6e 64 65 72 20 68 61 68 61 68 } //01 00  Stup windows defender hahah
		$a_01_1 = {5a 4d 38 23 39 61 75 4f 4d 63 41 2b 70 48 3c } //01 00  ZM8#9auOMcA+pH<
		$a_01_2 = {43 72 79 70 74 41 63 71 75 69 72 65 43 6f 6e 74 65 78 74 57 } //01 00  CryptAcquireContextW
		$a_01_3 = {43 72 79 70 74 49 6d 70 6f 72 74 4b 65 79 } //01 00  CryptImportKey
		$a_01_4 = {43 72 79 70 74 45 6e 63 72 79 70 74 } //01 00  CryptEncrypt
		$a_01_5 = {47 65 74 53 79 73 74 65 6d 4d 65 74 72 69 63 73 } //01 00  GetSystemMetrics
		$a_01_6 = {47 65 74 4d 6f 6e 69 74 6f 72 49 6e 66 6f 41 } //00 00  GetMonitorInfoA
	condition:
		any of ($a_*)
 
}