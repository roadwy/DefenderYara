
rule TrojanDownloader_BAT_Crysan_ACY_MTB{
	meta:
		description = "TrojanDownloader:BAT/Crysan.ACY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 03 00 00 "
		
	strings :
		$a_03_0 = {0a 04 16 6f ?? 00 00 0a 0a 06 14 28 ?? 00 00 0a 39 ?? 00 00 00 0e 04 04 25 3a ?? 00 00 00 26 72 ?? 00 00 70 51 16 0b } //2
		$a_03_1 = {0a 0b 07 72 ?? 00 00 70 6f ?? 00 00 0a 6f ?? 00 00 0a 6f ?? 00 00 0a 6f ?? 00 00 0a 6f ?? 00 00 0a 0a } //1
		$a_01_2 = {66 00 69 00 6c 00 65 00 63 00 72 00 75 00 6d 00 62 00 2e 00 6e 00 6c 00 2f 00 70 00 61 00 6e 00 65 00 6c 00 2f 00 75 00 70 00 6c 00 6f 00 61 00 64 00 73 00 2f 00 41 00 65 00 70 00 6e 00 7a 00 69 00 77 00 79 00 2e 00 77 00 61 00 76 00 } //5 filecrumb.nl/panel/uploads/Aepnziwy.wav
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1+(#a_01_2  & 1)*5) >=8
 
}