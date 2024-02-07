
rule Trojan_Win64_Farfli_CBH_MTB{
	meta:
		description = "Trojan:Win64/Farfli.CBH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 44 6f 63 75 6d 65 6e 74 73 5c 31 2e 65 78 65 } //01 00  C:\Users\Public\Documents\1.exe
		$a_01_1 = {43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 44 6f 63 75 6d 65 6e 74 73 5c 31 2e 74 78 74 } //01 00  C:\Users\Public\Documents\1.txt
		$a_01_2 = {68 74 74 70 3a 2f 2f 31 39 34 2e 33 36 2e 31 37 31 2e 39 32 3a 32 30 39 35 } //01 00  http://194.36.171.92:2095
		$a_81_3 = {43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 37 7a 2e 65 78 65 } //01 00  C:\ProgramData\7z.exe
		$a_01_4 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //01 00  IsDebuggerPresent
		$a_01_5 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //01 00  URLDownloadToFileA
		$a_01_6 = {47 65 74 54 69 63 6b 43 6f 75 6e 74 } //00 00  GetTickCount
	condition:
		any of ($a_*)
 
}