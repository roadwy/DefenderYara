
rule Trojan_Win32_Keylogger_AMBE_MTB{
	meta:
		description = "Trojan:Win32/Keylogger.AMBE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 05 00 00 05 00 "
		
	strings :
		$a_00_0 = {53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 64 00 65 00 66 00 39 00 62 00 36 00 63 00 64 00 33 00 66 00 32 00 62 00 30 00 63 00 34 00 33 00 30 00 39 00 37 00 64 00 66 00 62 00 63 00 39 00 31 00 38 00 38 00 36 00 32 00 62 00 38 00 32 00 } //05 00  Software\def9b6cd3f2b0c43097dfbc918862b82
		$a_01_1 = {4b 65 79 6c 6f 67 67 65 72 20 69 73 20 75 70 20 61 6e 64 20 72 75 6e 6e 69 6e 67 2e } //01 00  Keylogger is up and running.
		$a_01_2 = {53 65 74 43 6c 69 70 62 6f 61 72 64 44 61 74 61 } //01 00  SetClipboardData
		$a_01_3 = {4f 70 65 6e 43 6c 69 70 62 6f 61 72 64 } //01 00  OpenClipboard
		$a_01_4 = {47 65 74 4b 65 79 4e 61 6d 65 54 65 78 74 41 } //00 00  GetKeyNameTextA
	condition:
		any of ($a_*)
 
}