
rule Ransom_Win32_Royal_RPT_MTB{
	meta:
		description = "Ransom:Win32/Royal.RPT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 01 00 "
		
	strings :
		$a_01_0 = {52 00 45 00 41 00 44 00 4d 00 45 00 2e 00 54 00 58 00 54 00 } //01 00  README.TXT
		$a_01_1 = {2e 00 72 00 6f 00 79 00 61 00 6c 00 } //01 00  .royal
		$a_01_2 = {64 00 65 00 6c 00 65 00 74 00 65 00 20 00 73 00 68 00 61 00 64 00 6f 00 77 00 73 00 20 00 2f 00 61 00 6c 00 6c 00 20 00 2f 00 71 00 75 00 69 00 65 00 74 00 } //01 00  delete shadows /all /quiet
		$a_01_3 = {43 00 3a 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 53 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 76 00 73 00 73 00 61 00 64 00 6d 00 69 00 6e 00 2e 00 65 00 78 00 65 00 } //01 00  C:\Windows\System32\vssadmin.exe
		$a_01_4 = {2d 00 70 00 61 00 74 00 68 00 } //01 00  -path
		$a_01_5 = {47 65 74 4c 6f 67 69 63 61 6c 44 72 69 76 65 73 } //01 00  GetLogicalDrives
		$a_01_6 = {46 69 6e 64 46 69 72 73 74 46 69 6c 65 57 } //01 00  FindFirstFileW
		$a_01_7 = {46 69 6e 64 4e 65 78 74 46 69 6c 65 57 } //01 00  FindNextFileW
		$a_01_8 = {57 72 69 74 65 46 69 6c 65 } //01 00  WriteFile
		$a_01_9 = {43 72 79 70 74 41 63 71 75 69 72 65 43 6f 6e 74 65 78 74 57 } //00 00  CryptAcquireContextW
	condition:
		any of ($a_*)
 
}