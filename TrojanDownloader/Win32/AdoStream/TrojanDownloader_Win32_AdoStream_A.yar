
rule TrojanDownloader_Win32_AdoStream_A{
	meta:
		description = "TrojanDownloader:Win32/AdoStream.A,SIGNATURE_TYPE_PEHSTR,0c 00 0a 00 0c 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 65 74 20 48 54 54 50 47 45 54 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 4d 69 63 72 6f 73 6f 66 74 2e 58 4d 4c 48 54 54 50 22 29 } //01 00  Set HTTPGET = CreateObject("Microsoft.XMLHTTP")
		$a_01_1 = {53 65 74 20 53 65 6e 64 42 69 6e 61 72 79 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 41 44 4f 44 42 2e 53 74 72 65 61 6d 22 29 } //01 00  Set SendBinary = CreateObject("ADODB.Stream")
		$a_01_2 = {44 61 74 61 42 69 6e 20 3d 20 48 54 54 50 47 45 54 2e 52 65 73 70 6f 6e 73 65 42 6f 64 79 } //01 00  DataBin = HTTPGET.ResponseBody
		$a_01_3 = {43 6f 6e 73 74 20 61 64 53 61 76 65 43 72 65 61 74 65 4f 76 65 72 57 72 69 74 65 3d 32 } //01 00  Const adSaveCreateOverWrite=2
		$a_01_4 = {43 6f 6e 73 74 20 61 64 54 79 70 65 42 69 6e 61 72 79 3d 31 } //01 00  Const adTypeBinary=1
		$a_01_5 = {77 73 63 72 69 70 74 2e 65 78 65 20 2f 42 } //01 00  wscript.exe /B
		$a_01_6 = {63 73 63 72 69 70 74 2e 65 78 65 20 2f 42 } //01 00  cscript.exe /B
		$a_01_7 = {48 54 54 50 47 45 54 2e 53 65 6e 64 } //01 00  HTTPGET.Send
		$a_01_8 = {6d 73 68 74 61 2e 65 78 65 } //01 00  mshta.exe
		$a_01_9 = {56 00 42 00 53 00 63 00 72 00 69 00 70 00 74 00 } //01 00  VBScript
		$a_01_10 = {45 76 65 72 73 74 72 69 6b 65 20 53 6f 66 74 77 61 72 65 } //01 00  Everstrike Software
		$a_01_11 = {45 78 65 53 63 72 69 70 74 20 48 6f 73 74 } //00 00  ExeScript Host
	condition:
		any of ($a_*)
 
}