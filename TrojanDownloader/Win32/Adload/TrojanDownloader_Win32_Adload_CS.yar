
rule TrojanDownloader_Win32_Adload_CS{
	meta:
		description = "TrojanDownloader:Win32/Adload.CS,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 03 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 77 77 77 2e 6e 69 75 64 6f 75 64 6f 75 2e 63 6f 6d 2f 77 65 62 2f 64 6f 77 6e 6c 6f 61 64 2f } //4 http://www.niudoudou.com/web/download/
		$a_01_1 = {25 73 25 73 26 6d 61 63 68 69 6e 65 6e 61 6d 65 3d 25 73 } //2 %s%s&machinename=%s
		$a_01_2 = {67 65 74 5f 61 64 2e 61 73 70 3f 74 79 70 65 3d 6c 6f 61 64 61 6c 6c } //3 get_ad.asp?type=loadall
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*2+(#a_01_2  & 1)*3) >=9
 
}