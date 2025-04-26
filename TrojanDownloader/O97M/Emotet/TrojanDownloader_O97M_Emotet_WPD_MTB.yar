
rule TrojanDownloader_O97M_Emotet_WPD_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.WPD!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 06 00 00 "
		
	strings :
		$a_01_0 = {3a 2f 2f 65 61 73 69 65 72 63 6f 6d 6d 75 6e 69 63 61 74 69 6f 6e 73 2e 63 6f 6d 2f 77 70 2d 63 6f 6e 74 65 6e 74 2f 77 2f } //1 ://easiercommunications.com/wp-content/w/
		$a_01_1 = {3a 2f 2f 64 75 6c 69 63 68 64 69 63 68 76 75 2e 6e 65 74 2f 6c 69 62 72 61 72 69 65 73 2f 51 68 74 72 6a 43 5a 79 6d 4c 70 35 45 62 71 4f 64 70 4b 6b 2f } //1 ://dulichdichvu.net/libraries/QhtrjCZymLp5EbqOdpKk/
		$a_01_2 = {3a 2f 2f 77 77 77 2e 77 68 6f 77 2e 66 72 2f 77 70 2d 69 6e 63 6c 75 64 65 73 2f 48 35 34 46 67 6a 30 74 47 2f } //1 ://www.whow.fr/wp-includes/H54Fgj0tG/
		$a_01_3 = {3a 2f 2f 67 65 6e 63 63 61 67 64 61 73 2e 63 6f 6d 2e 74 72 2f 61 73 73 65 74 73 2f 54 54 48 4f 6d 38 33 33 69 4e 6e 33 42 78 54 2f } //1 ://genccagdas.com.tr/assets/TTHOm833iNn3BxT/
		$a_01_4 = {3a 2f 2f 68 65 61 76 65 6e 74 65 63 68 6e 6f 6c 6f 67 69 65 73 2e 63 6f 6d 2e 70 6b 2f 61 70 69 74 65 73 74 2f 78 64 65 41 55 30 72 78 32 36 4c 54 39 49 2f } //1 ://heaventechnologies.com.pk/apitest/xdeAU0rx26LT9I/
		$a_01_5 = {3a 2f 2f 67 6f 6f 6e 62 6f 79 2e 63 6f 6d 2f 67 6f 6f 6e 69 65 2f 62 53 46 7a 37 41 76 2f } //1 ://goonboy.com/goonie/bSFz7Av/
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=1
 
}