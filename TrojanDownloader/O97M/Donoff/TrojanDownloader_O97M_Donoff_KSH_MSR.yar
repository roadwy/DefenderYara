
rule TrojanDownloader_O97M_Donoff_KSH_MSR{
	meta:
		description = "TrojanDownloader:O97M/Donoff.KSH!MSR,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {2e 6d 70 2f 61 67 6b 61 6f 73 6b 61 73 66 6b 73 61 6b 64 61 6d 73 6b 64 6f 6b 61 73 64 6b 61 73 6f 64 6b 61 6f 73 } //1 .mp/agkaoskasfksakdamskdokasdkasodkaos
		$a_00_1 = {6d 73 67 62 6f 78 22 66 69 6c 65 69 73 63 6f 72 72 75 70 74 22 63 72 65 61 74 65 6f 62 6a 65 63 74 28 22 77 73 63 72 69 70 74 2e 73 68 65 6c 6c 22 29 2e 65 78 65 63 6d 61 69 6e 65 6e 64 73 75 62 } //1 msgbox"fileiscorrupt"createobject("wscript.shell").execmainendsub
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}
rule TrojanDownloader_O97M_Donoff_KSH_MSR_2{
	meta:
		description = "TrojanDownloader:O97M/Donoff.KSH!MSR,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_00_0 = {63 68 72 28 6c 6f 67 28 35 2e 39 39 30 30 33 34 33 33 33 30 34 38 31 65 2b 35 36 29 2f 6c 6f 67 28 33 29 29 26 5f 22 73 22 26 5f 22 63 72 69 70 22 26 5f 63 68 72 28 73 71 72 28 31 33 34 35 36 29 29 26 5f 22 2e 22 26 5f 63 68 72 28 73 71 72 28 31 33 32 32 35 29 29 26 5f 22 68 22 26 5f 22 65 22 26 5f 22 6c 22 26 5f 63 68 72 28 6c 6f 67 28 33 2e 33 38 31 33 39 31 39 31 33 35 32 32 37 33 65 2b 35 31 29 2f 6c 6f 67 28 33 29 29 } //1 chr(log(5.9900343330481e+56)/log(3))&_"s"&_"crip"&_chr(sqr(13456))&_"."&_chr(sqr(13225))&_"h"&_"e"&_"l"&_chr(log(3.38139191352273e+51)/log(3))
	condition:
		((#a_00_0  & 1)*1) >=1
 
}