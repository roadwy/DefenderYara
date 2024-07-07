
rule TrojanDownloader_Win32_Banload_AKX{
	meta:
		description = "TrojanDownloader:Win32/Banload.AKX,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {68 74 74 70 3a 2f 2f 64 6c 2e 64 72 6f 70 62 6f 78 2e 63 6f 6d 2f 75 2f 90 02 20 2e 70 64 66 90 00 } //1
		$a_01_1 = {77 69 6e 68 6f 73 74 2e 65 78 65 } //1 winhost.exe
		$a_01_2 = {54 61 73 6b 62 61 72 43 72 65 61 74 65 64 } //1 TaskbarCreated
		$a_01_3 = {43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c } //1 C:\ProgramData\
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}