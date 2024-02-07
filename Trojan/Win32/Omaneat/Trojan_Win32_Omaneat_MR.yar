
rule Trojan_Win32_Omaneat_MR{
	meta:
		description = "Trojan:Win32/Omaneat.MR,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 10 00 00 01 00 "
		
	strings :
		$a_81_0 = {66 62 68 72 6c 68 75 6d } //01 00  fbhrlhum
		$a_81_1 = {5c 54 45 4d 50 5c 35 75 72 70 64 33 70 34 6f } //01 00  \TEMP\5urpd3p4o
		$a_81_2 = {43 3a 5c 54 45 4d 50 5c 6e 73 6f 32 38 43 38 2e 74 6d 70 5c 6e 73 69 73 37 7a 2e 64 6c 6c } //01 00  C:\TEMP\nso28C8.tmp\nsis7z.dll
		$a_81_3 = {42 65 61 6d 20 57 61 6c 6c 65 74 } //01 00  Beam Wallet
		$a_81_4 = {52 45 50 41 52 53 45 5f 50 4f 49 4e 54 } //01 00  REPARSE_POINT
		$a_81_5 = {5c 45 78 65 63 43 6d 64 2e 64 6c 6c } //01 00  \ExecCmd.dll
		$a_81_6 = {53 50 41 52 53 45 5f 46 49 4c 45 7c } //01 00  SPARSE_FILE|
		$a_81_7 = {5c 57 6e 64 53 75 62 63 6c 61 73 73 2e 64 6c 6c } //01 00  \WndSubclass.dll
		$a_81_8 = {52 69 63 68 45 64 69 74 } //01 00  RichEdit
		$a_81_9 = {53 65 53 68 75 74 64 6f 77 6e 50 72 69 76 69 6c 65 67 65 } //01 00  SeShutdownPrivilege
		$a_81_10 = {52 65 67 44 65 6c 65 74 65 4b 65 79 45 78 41 } //01 00  RegDeleteKeyExA
		$a_81_11 = {53 79 73 4c 69 73 74 56 69 65 77 33 32 } //01 00  SysListView32
		$a_81_12 = {43 72 79 70 74 44 65 72 69 76 65 4b 65 79 } //01 00  CryptDeriveKey
		$a_81_13 = {43 72 79 70 74 45 6e 63 72 79 70 74 } //01 00  CryptEncrypt
		$a_81_14 = {43 72 79 70 74 44 65 73 74 72 6f 79 4b 65 79 } //01 00  CryptDestroyKey
		$a_81_15 = {43 72 79 70 74 52 65 6c 65 61 73 65 43 6f 6e 74 65 78 74 } //00 00  CryptReleaseContext
	condition:
		any of ($a_*)
 
}