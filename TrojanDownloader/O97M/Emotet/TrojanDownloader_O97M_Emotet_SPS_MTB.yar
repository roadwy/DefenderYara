
rule TrojanDownloader_O97M_Emotet_SPS_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.SPS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 04 00 00 "
		
	strings :
		$a_01_0 = {3a 2f 2f 70 72 70 72 6f 66 69 6c 65 2e 63 6f 6d 2f 77 70 2d 61 64 6d 69 6e 2f 43 49 71 72 76 67 59 73 76 42 69 42 6c 49 4d 2f 22 2c 22 } //1 ://prprofile.com/wp-admin/CIqrvgYsvBiBlIM/","
		$a_01_1 = {3a 2f 2f 72 65 74 61 72 64 61 6e 74 65 64 65 66 75 65 67 6f 70 65 72 75 2e 63 6f 6d 2f 73 6c 69 64 65 72 2f 72 46 68 41 61 37 38 2f 22 2c 22 } //1 ://retardantedefuegoperu.com/slider/rFhAa78/","
		$a_01_2 = {3a 2f 2f 73 75 72 76 65 69 2e 61 62 73 65 6e 73 69 2e 6e 65 74 2f 63 63 2d 63 6f 6e 74 65 6e 74 2f 59 43 63 6a 6b 4f 41 33 69 6a 59 4e 75 34 36 59 2f 22 2c 22 } //1 ://survei.absensi.net/cc-content/YCcjkOA3ijYNu46Y/","
		$a_01_3 = {3a 2f 2f 73 79 73 70 72 6f 63 2e 6e 65 74 2f 41 70 6c 69 6b 61 73 69 5f 61 74 6b 2f 69 4b 67 4f 6e 58 6a 6e 2f 22 2c 22 } //1 ://sysproc.net/Aplikasi_atk/iKgOnXjn/","
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=1
 
}