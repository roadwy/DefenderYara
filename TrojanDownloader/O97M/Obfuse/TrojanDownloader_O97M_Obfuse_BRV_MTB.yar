
rule TrojanDownloader_O97M_Obfuse_BRV_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BRV!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {4b 20 3d 20 22 64 69 61 6d 61 6e 74 65 73 76 69 61 67 65 6e 73 2e 63 6f 6d 2e 62 72 2f 22 } //1 K = "diamantesviagens.com.br/"
		$a_01_1 = {54 20 3d 20 22 56 69 72 75 73 45 6d 48 74 61 2e 6d 70 33 22 } //1 T = "VirusEmHta.mp3"
		$a_01_2 = {6d 65 69 6e 6b 6f 6e 68 75 6e 2e 45 58 45 43 20 70 69 6e 67 73 } //1 meinkonhun.EXEC pings
		$a_01_3 = {47 65 74 4f 62 6a 65 63 74 28 22 22 20 2b 20 22 6e 22 20 2b 20 22 65 22 20 2b 20 22 77 22 20 2b 20 22 3a 22 20 2b 20 } //1 GetObject("" + "n" + "e" + "w" + ":" + 
		$a_01_4 = {22 20 48 22 20 2b 20 44 20 2b 20 44 20 2b 20 4c 20 2b 20 22 3a 2f 2f 22 20 2b 20 4b 20 2b 20 54 } //1 " H" + D + D + L + "://" + K + T
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}