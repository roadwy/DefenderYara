
rule TrojanDownloader_O97M_Donoff_STEW_MTB{
	meta:
		description = "TrojanDownloader:O97M/Donoff.STEW!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {43 48 46 68 2e 4e 61 76 69 67 61 74 65 20 28 22 68 74 74 70 3a 2f 2f 31 39 32 2e 33 2e 37 36 2e 32 32 30 2f 6d 61 63 2e 74 78 74 22 29 } //1 CHFh.Navigate ("http://192.3.76.220/mac.txt")
		$a_01_1 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 42 49 74 6d 52 28 29 29 } //1 CreateObject(BItmR())
		$a_01_2 = {6c 4a 64 58 5a 47 2e 45 78 65 63 28 44 54 6c 57 48 28 29 29 } //1 lJdXZG.Exec(DTlWH())
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}