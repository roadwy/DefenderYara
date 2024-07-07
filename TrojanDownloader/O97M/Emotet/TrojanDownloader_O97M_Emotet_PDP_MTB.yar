
rule TrojanDownloader_O97M_Emotet_PDP_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.PDP!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 06 00 00 "
		
	strings :
		$a_01_0 = {3a 2f 2f 74 65 63 68 70 6c 61 6e 62 64 2e 78 79 7a 2f 71 65 6c 34 32 34 2f 52 53 7a 34 2f } //1 ://techplanbd.xyz/qel424/RSz4/
		$a_01_1 = {3a 2f 2f 6e 75 77 61 79 69 6e 74 65 72 6e 61 74 69 6f 6e 61 6c 2e 63 6f 6d 2f 6a 73 2f 45 4c 4e 6e 4c 30 69 6e 35 43 62 47 6e 48 6d 4e 63 2f } //1 ://nuwayinternational.com/js/ELNnL0in5CbGnHmNc/
		$a_01_2 = {3a 2f 2f 63 72 6d 2e 74 65 63 68 6f 70 65 73 6f 6c 75 74 69 6f 6e 73 2e 63 6f 6d 2f 74 74 74 77 78 6f 72 65 2f 69 68 7a 62 68 30 34 64 54 30 58 61 4a 47 41 66 2f } //1 ://crm.techopesolutions.com/tttwxore/ihzbh04dT0XaJGAf/
		$a_01_3 = {3a 2f 2f 73 74 65 65 6c 63 6f 72 70 2d 66 72 2e 63 6f 6d 2f 77 70 2d 63 6f 6e 74 65 6e 74 2f 74 6d 4d 46 57 30 53 4f 67 4f 6a 56 43 4f 2f } //1 ://steelcorp-fr.com/wp-content/tmMFW0SOgOjVCO/
		$a_01_4 = {3a 2f 2f 64 65 69 6e 65 2d 62 65 77 65 72 62 75 6e 67 2e 63 6f 6d 2f 77 70 2d 63 6f 6e 74 65 6e 74 2f 54 4b 58 70 6b 2f } //1 ://deine-bewerbung.com/wp-content/TKXpk/
		$a_01_5 = {3a 2f 2f 6c 69 76 65 6a 61 67 61 74 2e 63 6f 6d 2f 68 2f 4c 33 37 74 43 4d 36 70 70 53 2f } //1 ://livejagat.com/h/L37tCM6ppS/
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=1
 
}