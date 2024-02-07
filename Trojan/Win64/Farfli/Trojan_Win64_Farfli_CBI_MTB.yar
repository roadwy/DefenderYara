
rule Trojan_Win64_Farfli_CBI_MTB{
	meta:
		description = "Trojan:Win64/Farfli.CBI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 31 39 33 2e 31 36 34 2e 32 32 32 2e 31 33 31 3a 34 35 36 37 2f 37 37 } //01 00  http://193.164.222.131:4567/77
		$a_01_1 = {43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 44 6f 63 75 6d 65 6e 74 73 5c 73 76 63 68 6f 73 74 2e 74 78 74 } //01 00  C:\Users\Public\Documents\svchost.txt
		$a_01_2 = {43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 44 6f 63 75 6d 65 6e 74 73 5c 31 2e 72 61 72 } //01 00  C:\Users\Public\Documents\1.rar
		$a_81_3 = {43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 37 7a 2e 65 78 65 } //01 00  C:\ProgramData\7z.exe
		$a_01_4 = {43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 44 6f 63 75 6d 65 6e 74 73 5c 37 7a 2e 65 78 65 } //01 00  C:\Users\Public\Documents\7z.exe
		$a_01_5 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //01 00  IsDebuggerPresent
		$a_01_6 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //01 00  URLDownloadToFileA
		$a_01_7 = {47 65 74 54 69 63 6b 43 6f 75 6e 74 } //00 00  GetTickCount
	condition:
		any of ($a_*)
 
}