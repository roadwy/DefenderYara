
rule TrojanDownloader_Win32_Adload_BP{
	meta:
		description = "TrojanDownloader:Win32/Adload.BP,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {2f 63 6f 75 6e 74 5f 6c 69 76 65 2e 61 73 70 3f 65 78 65 63 3d } //1 /count_live.asp?exec=
		$a_01_1 = {2e 65 61 73 79 65 6e 63 6f 2e 63 6f 2e 6b 72 2f 6d 6f 64 75 6c 65 2f 63 6f 75 6e 74 2e 61 73 70 3f 65 78 65 63 3d } //1 .easyenco.co.kr/module/count.asp?exec=
		$a_01_2 = {2f 2f 2a 5b 40 72 61 6e 6b 20 3d 20 27 00 00 00 25 64 2d 25 64 2d 25 64 00 00 00 00 25 59 2d 25 6d 2d 25 64 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}