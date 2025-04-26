
rule TrojanDownloader_Win32_Minuplo_A{
	meta:
		description = "TrojanDownloader:Win32/Minuplo.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {6c 73 61 73 2e 65 78 65 00 } //1
		$a_01_1 = {6d 69 6e 69 75 70 6c 6f 61 64 2e 6e 65 74 2f 6d 65 2f 73 31 2e 70 68 70 } //1 miniupload.net/me/s1.php
		$a_01_2 = {6e 69 33 38 36 37 35 35 5f 33 2e 66 61 73 74 64 6f 77 6e 6c 6f 61 64 2e 6e 69 74 72 61 64 6f 2e 6e 65 74 2f 69 72 5f 75 70 64 61 74 65 78 2e 65 78 65 } //1 ni386755_3.fastdownload.nitrado.net/ir_updatex.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}