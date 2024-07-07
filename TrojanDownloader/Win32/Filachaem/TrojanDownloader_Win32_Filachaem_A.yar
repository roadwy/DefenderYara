
rule TrojanDownloader_Win32_Filachaem_A{
	meta:
		description = "TrojanDownloader:Win32/Filachaem.A,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 6d 75 73 61 68 2e 69 6e 66 6f 2f } //1 http://musah.info/
		$a_01_1 = {67 65 74 63 6f 6e 66 2e 70 68 70 } //1 getconf.php
		$a_01_2 = {64 6f 77 6e 5f 31 5f 66 69 6c 65 3a 20 21 66 69 6c 61 20 6e 65 74 21 20 2d 20 6b 61 63 68 61 65 6d 20 75 72 6c 3d } //1 down_1_file: !fila net! - kachaem url=
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}