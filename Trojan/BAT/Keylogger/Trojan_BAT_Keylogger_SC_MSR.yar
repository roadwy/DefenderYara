
rule Trojan_BAT_Keylogger_SC_MSR{
	meta:
		description = "Trojan:BAT/Keylogger.SC!MSR,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {4b 75 72 64 69 73 68 43 6f 64 65 72 50 72 6f 64 75 63 74 73 } //1 KurdishCoderProducts
		$a_01_1 = {53 00 45 00 4c 00 45 00 43 00 54 00 20 00 2a 00 20 00 46 00 52 00 4f 00 4d 00 20 00 43 00 75 00 73 00 74 00 6f 00 6d 00 65 00 72 00 73 00 } //1 SELECT * FROM Customers
		$a_01_2 = {44 00 61 00 74 00 61 00 47 00 72 00 69 00 64 00 56 00 69 00 65 00 77 00 50 00 72 00 69 00 6e 00 74 00 65 00 72 00 41 00 70 00 70 00 6c 00 69 00 63 00 61 00 74 00 69 00 6f 00 6e 00 2e 00 65 00 78 00 65 00 } //1 DataGridViewPrinterApplication.exe
		$a_01_3 = {4f 6c 65 44 62 44 61 74 61 } //1 OleDbData
		$a_01_4 = {45 64 69 74 6f 72 42 72 6f 77 73 61 62 6c 65 53 74 61 74 65 } //1 EditorBrowsableState
		$a_01_5 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 } //1 DebuggerNonUserCode
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}