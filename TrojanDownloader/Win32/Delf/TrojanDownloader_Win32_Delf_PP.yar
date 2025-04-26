
rule TrojanDownloader_Win32_Delf_PP{
	meta:
		description = "TrojanDownloader:Win32/Delf.PP,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 "
		
	strings :
		$a_01_0 = {73 00 33 00 2e 00 61 00 6d 00 61 00 7a 00 6f 00 6e 00 61 00 77 00 73 00 2e 00 63 00 6f 00 6d 00 2f 00 6a 00 6f 00 62 00 73 00 30 00 31 00 2f 00 63 00 6f 00 6d 00 70 00 69 00 6c 00 61 00 64 00 6f 00 73 00 2e 00 7a 00 69 00 70 00 } //1 s3.amazonaws.com/jobs01/compilados.zip
		$a_01_1 = {73 00 79 00 73 00 33 00 32 00 5c 00 63 00 6f 00 6d 00 70 00 69 00 6c 00 61 00 64 00 6f 00 73 00 2e 00 7a 00 69 00 70 00 } //1 sys32\compilados.zip
		$a_01_2 = {73 79 73 33 32 5c 73 6f 62 65 2e 65 78 65 } //1 sys32\sobe.exe
		$a_01_3 = {73 79 73 33 32 5c 4d 73 6e 2e 65 78 65 } //1 sys32\Msn.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=2
 
}