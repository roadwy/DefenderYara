
rule TrojanDownloader_Win32_Gployin_A_bit{
	meta:
		description = "TrojanDownloader:Win32/Gployin.A!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_02_0 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 69 00 6d 00 64 00 2e 00 67 00 64 00 79 00 69 00 70 00 69 00 6e 00 67 00 2e 00 63 00 6f 00 6d 00 90 02 30 2e 00 65 00 78 00 65 00 90 00 } //1
		$a_00_1 = {63 00 3a 00 5c 00 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 74 00 65 00 6d 00 70 00 5c 00 77 00 69 00 6e 00 6c 00 6f 00 67 00 6f 00 6e 00 2e 00 65 00 78 00 65 00 } //1 c:\windows\temp\winlogon.exe
		$a_00_2 = {73 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 6d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 63 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 72 00 75 00 6e 00 } //1 software\microsoft\windows\currentVersion\run
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}