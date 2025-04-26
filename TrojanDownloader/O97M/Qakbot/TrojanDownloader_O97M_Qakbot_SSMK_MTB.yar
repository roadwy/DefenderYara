
rule TrojanDownloader_O97M_Qakbot_SSMK_MTB{
	meta:
		description = "TrojanDownloader:O97M/Qakbot.SSMK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_01_0 = {74 70 73 3a 2f 2f 6d 69 2d 78 69 61 6f 6d 69 2e 6c 69 76 65 2f 79 54 69 4e 32 4a 4c 37 2f 4b 2e 70 6e 67 } //1 tps://mi-xiaomi.live/yTiN2JL7/K.png
		$a_01_1 = {74 74 70 73 3a 2f 2f 64 65 76 2e 61 70 62 2e 63 6f 6d 2e 6c 61 2f 53 31 64 42 54 56 31 79 54 2f 4b 2e 70 6e 67 } //1 ttps://dev.apb.com.la/S1dBTV1yT/K.png
		$a_01_2 = {74 74 70 73 3a 2f 2f 61 73 73 61 6d 63 61 72 65 65 72 2e 6e 65 77 73 2f 50 43 59 78 5a 42 70 62 66 77 4e 2f 4b 2e 70 6e 67 } //1 ttps://assamcareer.news/PCYxZBpbfwN/K.png
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=1
 
}
rule TrojanDownloader_O97M_Qakbot_SSMK_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Qakbot.SSMK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_01_0 = {74 74 70 73 3a 2f 2f 75 6e 69 72 6f 73 73 2e 73 69 74 65 2f 53 56 6d 47 74 46 57 55 4e 57 73 2f 49 2e 70 6e 67 } //1 ttps://uniross.site/SVmGtFWUNWs/I.png
		$a_01_1 = {74 74 70 73 3a 2f 2f 61 6c 65 78 61 64 72 69 76 69 6e 67 73 63 68 6f 6f 6c 2e 6f 6e 6c 69 6e 65 2f 56 69 61 61 77 4e 42 77 2f 49 2e 70 6e 67 } //1 ttps://alexadrivingschool.online/ViaawNBw/I.png
		$a_01_2 = {74 74 70 73 3a 2f 2f 61 64 62 6f 61 74 2e 6c 69 76 65 2f 54 43 41 31 6f 69 71 6b 41 2f 49 2e 70 6e 67 } //1 ttps://adboat.live/TCA1oiqkA/I.png
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=1
 
}
rule TrojanDownloader_O97M_Qakbot_SSMK_MTB_3{
	meta:
		description = "TrojanDownloader:O97M/Qakbot.SSMK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 04 00 00 "
		
	strings :
		$a_01_0 = {74 74 70 73 3a 2f 2f 6d 79 70 68 61 6d 63 75 61 74 75 69 2e 63 6f 6d 2f 61 73 73 65 74 73 2f 7a 31 62 39 59 66 48 6f 58 37 46 70 2f } //1 ttps://myphamcuatui.com/assets/z1b9YfHoX7Fp/
		$a_01_1 = {74 74 70 3a 2f 2f 6d 79 72 61 6d 61 72 6b 2e 63 6f 6d 2f 6d 61 69 6c 2f 72 68 45 50 79 6c 58 44 38 42 75 54 41 2f } //1 ttp://myramark.com/mail/rhEPylXD8BuTA/
		$a_01_2 = {74 74 70 73 3a 2f 2f 6d 79 65 63 68 6f 70 72 6f 6a 65 63 74 2e 63 6f 6d 2f 70 69 74 74 65 72 70 61 74 74 65 72 2f 62 4e 78 2f } //1 ttps://myechoproject.com/pitterpatter/bNx/
		$a_01_3 = {74 74 70 3a 2f 2f 6d 79 62 69 73 63 6f 74 74 6f 2e 63 6f 6d 2f 69 6d 61 67 65 73 2f 42 44 63 6a 51 54 2f } //1 ttp://mybiscotto.com/images/BDcjQT/
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=1
 
}