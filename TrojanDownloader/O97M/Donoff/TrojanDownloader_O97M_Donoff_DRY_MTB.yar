
rule TrojanDownloader_O97M_Donoff_DRY_MTB{
	meta:
		description = "TrojanDownloader:O97M/Donoff.DRY!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {4b 65 6e 20 73 69 73 74 65 72 73 20 77 76 } //1 Ken sisters wv
		$a_03_1 = {34 30 37 2e 63 64 2e 67 6f 76 2e 6d 6e 2f 5f 57 35 34 73 45 6f 5a 4b 6c 2d 6d 32 77 36 52 5a 2e 70 68 70 3f 78 3d 4d 44 41 77 4d 53 44 71 75 46 6a 6e 6e 51 66 4e 73 6b 75 51 77 58 53 46 70 79 48 30 5a 39 90 0a 4b 00 68 74 74 70 3a 2f 2f 90 00 } //1
		$a_01_2 = {79 76 2e 65 78 65 63 20 22 72 65 67 73 76 72 33 32 20 63 3a 5c 70 72 6f 67 72 61 6d 64 61 74 61 5c 31 2e 64 61 74 } //1 yv.exec "regsvr32 c:\programdata\1.dat
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule TrojanDownloader_O97M_Donoff_DRY_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Donoff.DRY!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 07 00 00 "
		
	strings :
		$a_01_0 = {22 77 22 20 2b 20 22 2e 22 20 2b 20 22 62 22 20 2b 20 22 69 22 20 2b 20 22 74 22 20 2b 20 22 6c 22 20 2b 20 22 79 22 20 2b 20 22 2e 22 20 2b 20 22 63 22 20 2b 20 22 6f 22 20 2b 20 22 6d 2f 68 77 64 69 6e 6e 77 73 6e 77 64 64 6b 77 6d 6b 77 6d 6d 77 71 77 68 64 61 22 } //1 "w" + "." + "b" + "i" + "t" + "l" + "y" + "." + "c" + "o" + "m/hwdinnwsnwddkwmkwmmwqwhda"
		$a_01_1 = {22 77 22 20 2b 20 22 2e 22 20 2b 20 22 62 22 20 2b 20 22 69 22 20 2b 20 22 74 22 20 2b 20 22 6c 22 20 2b 20 22 79 22 20 2b 20 22 2e 22 20 2b 20 22 63 22 20 2b 20 22 6f 22 20 2b 20 22 6d 2f 68 77 64 69 6e 6e 77 73 6e 6b 64 77 6d 77 71 77 68 64 61 22 } //1 "w" + "." + "b" + "i" + "t" + "l" + "y" + "." + "c" + "o" + "m/hwdinnwsnkdwmwqwhda"
		$a_01_2 = {22 77 22 20 2b 20 22 2e 22 20 2b 20 22 62 22 20 2b 20 22 69 22 20 2b 20 22 74 22 20 2b 20 22 6c 22 20 2b 20 22 79 22 20 2b 20 22 2e 22 20 2b 20 22 63 22 20 2b 20 22 6f 22 20 2b 20 22 6d 2f 68 77 64 69 6e 6e 77 73 6e 6b 64 77 77 64 6d 6e 6d 77 71 77 68 64 61 22 } //1 "w" + "." + "b" + "i" + "t" + "l" + "y" + "." + "c" + "o" + "m/hwdinnwsnkdwwdmnmwqwhda"
		$a_01_3 = {70 75 62 6c 69 63 25 22 } //1 public%"
		$a_01_4 = {53 57 5f 53 48 4f 57 4d 69 6e 69 6d 69 7a 65 29 } //1 SW_SHOWMinimize)
		$a_01_5 = {53 57 5f 53 48 4f 57 4d 41 58 49 4d 49 5a 45 44 } //1 SW_SHOWMAXIMIZED
		$a_01_6 = {28 30 2c 20 22 6f 70 65 6e 22 2c 20 6b 6f 6b 6f 2c 20 22 68 22 } //1 (0, "open", koko, "h"
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=5
 
}