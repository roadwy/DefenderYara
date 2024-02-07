
rule Trojan_Win32_Farfli_RPQ_MTB{
	meta:
		description = "Trojan:Win32/Farfli.RPQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {62 61 74 69 79 61 2e 65 78 65 } //01 00  batiya.exe
		$a_01_1 = {50 72 6f 67 72 61 6d 44 61 74 61 5c 68 6f 6d 6f 5c 32 2e 65 78 65 } //01 00  ProgramData\homo\2.exe
		$a_01_2 = {31 35 34 2e 33 39 2e 32 33 39 2e 32 30 32 } //01 00  154.39.239.202
		$a_01_3 = {74 6f 63 6b 2e 65 78 65 } //01 00  tock.exe
		$a_01_4 = {74 65 73 74 2e 65 78 65 } //01 00  test.exe
		$a_01_5 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //01 00  URLDownloadToFileA
		$a_01_6 = {53 68 65 6c 6c 45 78 65 63 75 74 65 41 } //01 00  ShellExecuteA
		$a_01_7 = {53 6c 65 65 70 } //00 00  Sleep
	condition:
		any of ($a_*)
 
}