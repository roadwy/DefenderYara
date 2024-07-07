
rule Trojan_Win32_Keylogger_AMBE_MTB{
	meta:
		description = "Trojan:Win32/Keylogger.AMBE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 05 00 00 "
		
	strings :
		$a_00_0 = {53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 64 00 65 00 66 00 39 00 62 00 36 00 63 00 64 00 33 00 66 00 32 00 62 00 30 00 63 00 34 00 33 00 30 00 39 00 37 00 64 00 66 00 62 00 63 00 39 00 31 00 38 00 38 00 36 00 32 00 62 00 38 00 32 00 } //5 Software\def9b6cd3f2b0c43097dfbc918862b82
		$a_01_1 = {4b 65 79 6c 6f 67 67 65 72 20 69 73 20 75 70 20 61 6e 64 20 72 75 6e 6e 69 6e 67 2e } //5 Keylogger is up and running.
		$a_01_2 = {53 65 74 43 6c 69 70 62 6f 61 72 64 44 61 74 61 } //1 SetClipboardData
		$a_01_3 = {4f 70 65 6e 43 6c 69 70 62 6f 61 72 64 } //1 OpenClipboard
		$a_01_4 = {47 65 74 4b 65 79 4e 61 6d 65 54 65 78 74 41 } //1 GetKeyNameTextA
	condition:
		((#a_00_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=13
 
}
rule Trojan_Win32_Keylogger_AMBE_MTB_2{
	meta:
		description = "Trojan:Win32/Keylogger.AMBE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {61 48 52 30 63 44 6f 76 4c 33 52 6c 63 6d 56 69 61 57 35 75 59 57 68 70 59 32 4d 75 59 32 78 31 59 69 39 7a 5a 57 4d 76 61 32 39 76 62 43 35 30 65 48 51 } //1 aHR0cDovL3RlcmViaW5uYWhpY2MuY2x1Yi9zZWMva29vbC50eHQ
		$a_00_1 = {6f 00 79 00 37 00 6f 00 65 00 6c 00 30 00 31 00 34 00 70 00 67 00 78 00 33 00 72 00 6e 00 6d 00 67 00 6f 00 31 00 66 00 6c 00 6f 00 79 00 74 00 74 00 34 00 6f 00 38 00 65 00 67 00 68 00 61 00 70 00 7a 00 75 00 6f 00 6e 00 37 00 30 00 66 00 68 00 72 00 75 00 30 00 6c 00 6e 00 6c 00 73 00 76 00 } //1 oy7oel014pgx3rnmgo1floytt4o8eghapzuon70fhru0lnlsv
		$a_00_2 = {28 00 31 00 7c 00 33 00 29 00 5b 00 31 00 2d 00 39 00 41 00 2d 00 48 00 4a 00 2d 00 4e 00 50 00 2d 00 5a 00 61 00 2d 00 6b 00 6d 00 2d 00 7a 00 5d 00 7b 00 32 00 36 00 2c 00 33 00 34 00 7d 00 24 00 } //1 (1|3)[1-9A-HJ-NP-Za-km-z]{26,34}$
	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}