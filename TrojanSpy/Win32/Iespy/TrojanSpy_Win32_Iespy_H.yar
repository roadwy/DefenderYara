
rule TrojanSpy_Win32_Iespy_H{
	meta:
		description = "TrojanSpy:Win32/Iespy.H,SIGNATURE_TYPE_PEHSTR_EXT,36 00 32 00 08 00 00 0a 00 "
		
	strings :
		$a_00_0 = {53 59 53 54 45 4d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 53 65 72 76 69 63 65 73 5c 42 49 54 53 } //0a 00  SYSTEM\CurrentControlSet\Services\BITS
		$a_00_1 = {25 73 53 65 74 75 70 25 64 2e 65 78 65 } //0a 00  %sSetup%d.exe
		$a_00_2 = {69 6c 6f 76 65 79 6f 75 66 75 63 6b 74 68 65 77 6f 72 6c 64 } //0a 00  iloveyoufucktheworld
		$a_02_3 = {68 74 74 70 3a 2f 2f 90 02 20 2f 64 6f 77 6e 2e 67 69 66 90 00 } //0a 00 
		$a_02_4 = {68 74 74 70 3a 2f 2f 90 02 20 2f 63 68 65 63 6b 2e 61 73 70 90 00 } //04 00 
		$a_00_5 = {62 00 69 00 74 00 73 00 2e 00 64 00 6c 00 6c 00 } //02 00  bits.dll
		$a_00_6 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //02 00  URLDownloadToFileA
		$a_00_7 = {53 68 65 6c 6c 45 78 65 63 75 74 65 41 } //00 00  ShellExecuteA
	condition:
		any of ($a_*)
 
}