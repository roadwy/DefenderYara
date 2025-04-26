
rule TrojanDownloader_BAT_Demero_A{
	meta:
		description = "TrojanDownloader:BAT/Demero.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {09 11 04 9a 6f 14 00 00 0a 00 00 de 05 26 00 00 de 00 00 00 11 04 17 58 13 04 11 04 09 8e 69 fe 04 13 09 11 09 2d d7 } //1
		$a_03_1 = {63 3a 5c 55 73 65 72 73 5c 45 6d 72 65 5c 44 65 73 6b 74 6f 70 5c [0-01] 45 78 74 65 6e 73 69 6f 6e 5c 44 6f 77 6e 6c 6f 61 64 65 72 } //1
		$a_00_2 = {5c 00 49 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 65 00 72 00 2e 00 65 00 78 00 65 00 } //1 \Installer.exe
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}