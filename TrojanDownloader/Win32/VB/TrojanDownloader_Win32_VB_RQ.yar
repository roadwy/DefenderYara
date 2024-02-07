
rule TrojanDownloader_Win32_VB_RQ{
	meta:
		description = "TrojanDownloader:Win32/VB.RQ,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0a 00 05 00 00 05 00 "
		
	strings :
		$a_01_0 = {63 00 3a 00 5c 00 6f 00 69 00 65 00 64 00 2e 00 62 00 61 00 6b 00 2e 00 76 00 62 00 73 00 } //01 00  c:\oied.bak.vbs
		$a_01_1 = {43 00 3a 00 5c 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 20 00 46 00 69 00 6c 00 65 00 73 00 5c 00 73 00 74 00 61 00 74 00 69 00 63 00 69 00 61 00 6c 00 } //01 00  C:\Program Files\staticial
		$a_01_2 = {43 00 3a 00 5c 00 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 73 00 74 00 61 00 74 00 69 00 63 00 69 00 61 00 6c 00 } //01 00  C:\windows\staticial
		$a_01_3 = {5c 00 63 00 6d 00 73 00 73 00 2e 00 6a 00 79 00 63 00 2c 00 73 00 63 00 61 00 6e 00 4d 00 69 00 64 00 64 00 6c 00 65 00 } //05 00  \cmss.jyc,scanMiddle
		$a_01_4 = {63 6d 63 2e 63 78 65 20 2f 63 20 69 70 63 6f 6e 66 69 67 20 2f 61 6c 6c 20 3e 20 63 3a 5c 57 49 4e 44 4f 57 53 5c 54 65 6d 70 5c 32 30 32 30 2e 74 6d 70 } //00 00  cmc.cxe /c ipconfig /all > c:\WINDOWS\Temp\2020.tmp
	condition:
		any of ($a_*)
 
}