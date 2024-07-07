
rule TrojanDownloader_O97M_Emotet_OWSU_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.OWSU!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 73 68 6f 70 2e 6c 61 6d 62 6f 6c 65 72 6f 2e 63 6f 6d 2f 69 69 77 6b 6a 67 70 2f 65 75 37 72 48 36 2f } //1 http://shop.lambolero.com/iiwkjgp/eu7rH6/
		$a_01_1 = {68 74 74 70 3a 2f 2f 61 70 69 2e 74 61 73 6b 2d 6c 69 74 65 2e 63 6f 6d 2f 2d 2f 45 59 65 33 44 45 66 63 77 37 4c 43 61 55 36 54 2f } //1 http://api.task-lite.com/-/EYe3DEfcw7LCaU6T/
		$a_01_2 = {68 74 74 70 73 3a 2f 2f 63 65 6c 68 6f 63 6f 72 74 6f 66 69 6c 6d 66 65 73 74 69 76 61 6c 2e 73 74 72 65 61 6d 2f 63 73 73 2f 6f 51 53 42 72 34 34 6f 62 45 2f } //1 https://celhocortofilmfestival.stream/css/oQSBr44obE/
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=1
 
}