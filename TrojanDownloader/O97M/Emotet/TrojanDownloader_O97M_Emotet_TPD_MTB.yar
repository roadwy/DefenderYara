
rule TrojanDownloader_O97M_Emotet_TPD_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.TPD!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 06 00 00 "
		
	strings :
		$a_01_0 = {65 6c 65 73 65 6c 65 6b 74 72 6f 6d 65 6b 61 6e 69 6b 2e 63 6f 6d 2f 36 39 49 71 35 50 77 62 64 30 2f 73 2f } //1 eleselektromekanik.com/69Iq5Pwbd0/s/
		$a_01_1 = {64 65 6d 6f 2e 69 63 6e 2e 63 6f 6d 2e 6e 70 2f 73 74 6f 72 69 65 73 2f 51 6b 2f } //1 demo.icn.com.np/stories/Qk/
		$a_01_2 = {64 65 6d 6f 33 34 2e 63 6b 67 2e 68 6b 2f 73 65 72 76 69 63 65 2f 41 74 6b 37 52 51 66 55 56 36 37 33 4d 2f } //1 demo34.ckg.hk/service/Atk7RQfUV673M/
		$a_01_3 = {62 69 74 6d 6f 76 69 6c 2e 6d 78 2f 63 73 73 2f 54 72 67 79 50 69 54 58 79 33 2f } //1 bitmovil.mx/css/TrgyPiTXy3/
		$a_01_4 = {64 75 70 6f 74 2e 63 7a 2f 74 76 68 6f 73 74 2f 44 55 6e 4d 55 76 77 5a 4f 68 51 73 2f } //1 dupot.cz/tvhost/DUnMUvwZOhQs/
		$a_01_5 = {66 6f 63 61 6e 61 69 6e 74 65 72 6e 65 74 2e 63 6f 6d 2e 62 72 2f 65 72 72 6f 73 2f 44 65 70 41 4b 33 70 31 59 2f } //1 focanainternet.com.br/erros/DepAK3p1Y/
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=1
 
}