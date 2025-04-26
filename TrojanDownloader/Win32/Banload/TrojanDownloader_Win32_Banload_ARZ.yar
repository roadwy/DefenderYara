
rule TrojanDownloader_Win32_Banload_ARZ{
	meta:
		description = "TrojanDownloader:Win32/Banload.ARZ,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {43 00 48 00 41 00 56 00 45 00 3d 00 5b 00 27 00 5d 00 } //1 CHAVE=[']
		$a_01_1 = {2f 00 6e 00 6f 00 74 00 69 00 66 00 79 00 2e 00 70 00 68 00 70 00 } //1 /notify.php
		$a_01_2 = {5c 41 56 41 53 54 20 53 6f 66 74 77 61 72 65 5c 41 76 61 73 74 5c 73 65 74 75 70 } //1 \AVAST Software\Avast\setup
		$a_03_3 = {61 00 70 00 70 00 64 00 61 00 74 00 61 00 [0-10] 68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}