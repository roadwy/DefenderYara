
rule TrojanDownloader_Win32_Matcash_K{
	meta:
		description = "TrojanDownloader:Win32/Matcash.K,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {77 77 6c 61 78 2e 63 6f 6d 2f 67 65 74 5f 66 72 73 74 2e 70 68 70 3f } //1 wwlax.com/get_frst.php?
		$a_01_1 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //1 URLDownloadToFileA
		$a_01_2 = {64 00 00 65 6c 00 00 20 22 00 00 25 73 00 00 6f 70 65 6e 00 00 00 00 68 74 00 00 74 70 00 00 63 6c 61 73 73 00 00 00 2e 00 00 00 77 77 00 00 6c 61 00 00 78 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}