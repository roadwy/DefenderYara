
rule TrojanDownloader_Win32_Banload_IK{
	meta:
		description = "TrojanDownloader:Win32/Banload.IK,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_00_0 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 } //1 SOFTWARE\Borland\Delphi
		$a_00_1 = {43 72 65 61 74 65 50 72 6f 63 65 73 73 28 6e 69 6c 2c 70 63 68 61 72 28 } //1 CreateProcess(nil,pchar(
		$a_00_2 = {24 2b 72 2b 24 5c 62 69 6e 5c 64 63 63 33 32 2e 65 78 65 22 } //1 $+r+$\bin\dcc32.exe"
		$a_00_3 = {67 65 74 68 6f 73 74 62 79 6e 61 6d 65 } //1 gethostbyname
		$a_00_4 = {4d 6f 7a 69 6c 6c 61 2f 33 2e 30 20 28 63 6f 6d 70 61 74 69 62 6c 65 3b 20 49 6e 64 79 20 4c 69 62 72 61 72 79 29 } //1 Mozilla/3.0 (compatible; Indy Library)
		$a_02_5 = {68 74 74 70 3a 2f 2f 77 77 77 2e [0-20] 2e 68 70 67 2e 63 6f 6d 2e 62 72 2f [0-10] 2e 6a 70 67 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_02_5  & 1)*1) >=6
 
}