
rule TrojanDownloader_O97M_Emulasev_A{
	meta:
		description = "TrojanDownloader:O97M/Emulasev.A,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {45 31 4d 77 4c 61 55 37 30 37 20 56 51 75 77 64 6a 43 4b 7a 66 62 62 61 66 50 28 22 68 90 01 01 74 90 01 01 74 90 01 01 70 90 00 } //1
		$a_03_1 = {45 6e 76 69 72 6f 6e 28 56 51 75 77 64 6a 43 4b 7a 66 62 62 61 66 50 28 22 54 90 01 01 4d 90 01 01 50 90 00 } //1
		$a_01_2 = {56 51 75 77 64 6a 43 4b 7a 66 62 62 61 66 50 28 } //1 VQuwdjCKzfbbafP(
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}