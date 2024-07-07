
rule TrojanDownloader_Win32_Vitero_A{
	meta:
		description = "TrojanDownloader:Win32/Vitero.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {2e 74 6f 2e 38 38 36 36 2e 6f 72 67 } //1 .to.8866.org
		$a_01_1 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //1 URLDownloadToFileA
		$a_01_2 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 44 72 69 76 65 72 73 33 32 5c } //1 SOFTWARE\Microsoft\Windows NT\CurrentVersion\Drivers32\
		$a_01_3 = {4e 74 53 68 75 74 64 6f 77 6e 53 79 73 74 65 6d } //1 NtShutdownSystem
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}