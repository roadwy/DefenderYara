
rule TrojanDownloader_O97M_Emotet_PDM_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.PDM!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 06 00 00 "
		
	strings :
		$a_01_0 = {3a 2f 2f 66 6f 72 6f 76 69 76 69 65 6e 64 61 70 61 72 61 67 75 61 79 2e 63 6f 6d 2f 77 70 2d 61 64 6d 69 6e 2f 68 78 38 55 36 58 4d 66 66 6e 6b 76 38 48 49 32 4f 69 67 2f } //1 ://foroviviendaparaguay.com/wp-admin/hx8U6XMffnkv8HI2Oig/
		$a_01_1 = {3a 2f 2f 65 6e 2e 70 61 63 68 61 6d 6d 65 72 2e 63 6f 6d 2f 77 70 2d 63 6f 6e 74 65 6e 74 2f 76 49 47 2f } //1 ://en.pachammer.com/wp-content/vIG/
		$a_01_2 = {3a 2f 2f 67 68 73 6a 61 6c 6b 68 65 72 61 62 73 72 2e 63 6f 6d 2f 6f 7a 30 33 6e 2f 36 58 65 59 4c 6a 46 58 63 46 45 2f } //1 ://ghsjalkherabsr.com/oz03n/6XeYLjFXcFE/
		$a_01_3 = {3a 2f 2f 67 68 73 6d 61 64 6f 6e 61 62 73 72 2e 63 6f 6d 2f 77 70 2d 69 6e 63 6c 75 64 65 73 2f 4f 66 34 6b 51 4e 43 70 32 57 4c 79 30 46 34 42 2f } //1 ://ghsmadonabsr.com/wp-includes/Of4kQNCp2WLy0F4B/
		$a_01_4 = {3a 2f 2f 77 77 77 2e 61 61 63 69 74 79 67 72 6f 75 70 2e 63 6f 6d 2f 77 70 2d 63 6f 6e 74 65 6e 74 2f 45 6b 59 39 2f } //1 ://www.aacitygroup.com/wp-content/EkY9/
		$a_01_5 = {3a 2f 2f 74 68 65 6f 75 74 73 6f 75 72 63 65 64 61 63 63 6f 75 6e 74 61 6e 74 2e 63 6f 6d 2f 69 6d 61 67 65 73 2f 6e 46 69 6b 54 51 6d 50 2f } //1 ://theoutsourcedaccountant.com/images/nFikTQmP/
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=1
 
}