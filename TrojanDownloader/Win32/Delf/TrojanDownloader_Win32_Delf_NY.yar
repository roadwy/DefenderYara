
rule TrojanDownloader_Win32_Delf_NY{
	meta:
		description = "TrojanDownloader:Win32/Delf.NY,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 77 77 77 2e 62 76 6c 65 6f 2e 62 6c 6f 67 67 65 72 2e 63 6f 6d 2e 62 72 2f 47 61 6c 65 72 61 25 32 30 64 61 25 32 30 46 61 63 75 25 32 30 65 6d 25 32 30 50 69 72 61 70 6f 72 61 2e 6a 70 67 } //3 http://www.bvleo.blogger.com.br/Galera%20da%20Facu%20em%20Pirapora.jpg
		$a_01_1 = {2f 69 6e 73 74 61 6c 6c 20 2f 73 69 6c 65 6e 74 } //2 /install /silent
		$a_01_2 = {68 74 74 70 3a 2f 2f 64 6c 2e 64 72 6f 70 62 6f 78 2e 63 6f 6d 2f } //2 http://dl.dropbox.com/
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=7
 
}