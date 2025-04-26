
rule TrojanDownloader_O97M_Emotet_STKV_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.STKV!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 04 00 00 "
		
	strings :
		$a_01_0 = {3a 2f 2f 74 76 73 74 76 2e 79 75 6e 65 74 68 6f 73 74 69 6e 67 2e 72 73 2f 6e 65 73 63 69 75 6e 74 71 75 6f 73 2f 32 53 6c 72 53 64 4c 42 41 76 37 2f 22 } //1 ://tvstv.yunethosting.rs/nesciuntquos/2SlrSdLBAv7/"
		$a_01_1 = {3a 2f 2f 77 61 68 6b 69 75 6c 6f 67 69 73 74 69 63 73 2e 63 6f 6d 2e 68 6b 2f 75 70 6c 6f 61 64 2f 72 49 70 55 6d 69 37 4d 72 6c 4f 63 2f 22 } //1 ://wahkiulogistics.com.hk/upload/rIpUmi7MrlOc/"
		$a_01_2 = {3a 2f 2f 76 61 6e 6c 61 65 72 65 69 63 74 2e 6e 6c 2f 64 6f 6d 61 69 6e 73 2f 54 39 47 35 72 75 51 4a 2f 22 } //1 ://vanlaereict.nl/domains/T9G5ruQJ/"
		$a_01_3 = {3a 2f 2f 75 73 61 2d 6c 74 64 2e 69 65 2f 77 70 2d 69 6e 63 6c 75 64 65 73 2f 30 78 37 48 50 6c 5a 38 73 47 41 4e 69 49 35 69 2f 22 } //1 ://usa-ltd.ie/wp-includes/0x7HPlZ8sGANiI5i/"
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=1
 
}