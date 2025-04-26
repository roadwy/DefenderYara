
rule TrojanDownloader_O97M_Emotet_EPD_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.EPD!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 07 00 00 "
		
	strings :
		$a_01_0 = {3a 2f 2f 77 77 77 2e 61 6c 65 6a 61 6e 64 72 6f 76 69 6c 6c 61 72 2e 63 6f 6d 2f 4d 53 4c 2f 65 4b 44 57 6a 70 61 34 4f 48 52 78 70 79 73 4f 54 46 65 2f } //1 ://www.alejandrovillar.com/MSL/eKDWjpa4OHRxpysOTFe/
		$a_01_1 = {3a 2f 2f 61 6c 65 6a 61 6e 64 72 61 73 74 61 6d 61 74 65 61 73 2e 63 6f 6d 2f 77 65 62 2f 5a 78 41 33 7a 48 77 73 48 33 72 2f } //1 ://alejandrastamateas.com/web/ZxA3zHwsH3r/
		$a_01_2 = {3a 2f 2f 61 6c 65 78 65 74 61 75 72 6f 72 65 2e 63 6f 6d 2f 77 61 6e 74 65 64 2f 70 66 46 74 7a 61 4a 6f 76 49 43 55 38 31 6b 66 75 55 70 2f } //1 ://alexetaurore.com/wanted/pfFtzaJovICU81kfuUp/
		$a_01_3 = {3a 2f 2f 61 79 75 72 73 6f 75 6b 68 79 61 2e 6f 72 67 2f 77 70 2d 69 6e 63 6c 75 64 65 73 2f 58 49 33 35 71 50 47 48 76 73 7a 5a 31 75 2f } //1 ://ayursoukhya.org/wp-includes/XI35qPGHvszZ1u/
		$a_01_4 = {3a 2f 2f 62 61 6c 69 62 75 6c 69 2e 68 75 2f 63 67 69 2d 62 69 6e 2f 57 44 44 4d 30 56 48 53 4b 34 56 63 4f 46 6d 55 2f } //1 ://balibuli.hu/cgi-bin/WDDM0VHSK4VcOFmU/
		$a_01_5 = {3a 2f 2f 61 6c 64 69 62 69 6b 69 2e 63 6f 6d 2f 70 72 65 74 74 79 50 68 6f 74 6f 2f 67 4c 46 52 7a 51 56 30 56 75 6e 4f 2f } //1 ://aldibiki.com/prettyPhoto/gLFRzQV0VunO/
		$a_01_6 = {3a 2f 2f 61 6c 2d 62 72 69 6b 2e 63 6f 6d 2f 76 62 2d 77 2f 55 2f } //1 ://al-brik.com/vb-w/U/
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=1
 
}