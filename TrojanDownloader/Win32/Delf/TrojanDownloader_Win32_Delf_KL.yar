
rule TrojanDownloader_Win32_Delf_KL{
	meta:
		description = "TrojanDownloader:Win32/Delf.KL,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_00_0 = {55 73 65 72 2d 61 67 65 6e 74 3a 20 4d 6f 7a 69 6c 6c 61 2f 34 2e 30 } //1 User-agent: Mozilla/4.0
		$a_00_1 = {64 6f 77 6c 6f 61 64 20 73 75 63 65 73 73 66 75 6c 6c } //1 dowload sucessfull
		$a_00_2 = {6c 6f 61 64 69 6e 67 20 73 75 63 65 73 73 66 75 6c 6c } //1 loading sucessfull
		$a_02_3 = {43 61 70 74 69 6f 6e [0-10] 4d 53 73 65 63 75 72 69 74 79 33 32 } //1
		$a_00_4 = {74 79 6d 69 6e 67 20 6c 6f 61 64 } //1 tyming load
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_02_3  & 1)*1+(#a_00_4  & 1)*1) >=4
 
}