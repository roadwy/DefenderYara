
rule TrojanDownloader_O97M_Donoff_PB{
	meta:
		description = "TrojanDownloader:O97M/Donoff.PB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_00_0 = {68 74 74 70 3a 2f 2f 67 65 63 68 79 2e 72 75 2f 68 61 6e 67 65 72 2f } //3 http://gechy.ru/hanger/
		$a_02_1 = {3d 20 22 63 6d 64 2e 65 78 65 20 2f 63 22 20 26 20 22 43 6d 44 20 90 02 10 22 20 26 20 22 20 63 6d 64 20 22 20 26 20 22 2f 63 22 20 26 90 00 } //1
		$a_00_2 = {25 54 45 4d 50 25 5c 70 2e 73 63 72 22 20 26 } //1 %TEMP%\p.scr" &
		$a_02_3 = {3d 20 53 68 65 6c 6c 28 90 02 10 2c 20 31 20 2f 20 32 2e 35 29 90 00 } //1
	condition:
		((#a_00_0  & 1)*3+(#a_02_1  & 1)*1+(#a_00_2  & 1)*1+(#a_02_3  & 1)*1) >=3
 
}