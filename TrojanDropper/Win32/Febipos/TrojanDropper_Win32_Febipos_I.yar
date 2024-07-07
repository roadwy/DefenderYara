
rule TrojanDropper_Win32_Febipos_I{
	meta:
		description = "TrojanDropper:Win32/Febipos.I,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 08 00 00 "
		
	strings :
		$a_03_0 = {3c 09 75 e7 0f b6 03 3c 20 75 73 83 c3 01 0f b6 03 3c 09 74 f6 3c 20 74 f2 f6 45 d0 01 be 0a 00 00 00 74 04 0f b7 75 d4 c7 04 24 00 00 00 00 e8 90 01 04 83 ec 04 89 74 24 0c 89 5c 24 08 c7 44 24 04 00 00 00 00 89 04 24 e8 90 00 } //5
		$a_01_1 = {79 74 6e 65 77 73 2e 69 6e 66 6f 2f 73 68 6f 77 63 6f 75 6e 74 72 79 2e 70 68 70 } //5 ytnews.info/showcountry.php
		$a_01_2 = {77 68 6f 73 2e 61 6d 75 6e 67 2e 75 73 2f 77 69 64 67 65 74 2f 6f 6b 69 6e 73 74 61 6c 6c 62 72 61 2e 70 6e 68 } //1 whos.amung.us/widget/okinstallbra.pnh
		$a_01_3 = {22 69 6e 73 74 61 6c 6c 5f 74 69 6d 65 22 3a 20 22 31 33 30 35 34 37 38 35 39 32 31 31 34 35 38 31 32 22 } //1 "install_time": "13054785921145812"
		$a_01_4 = {25 73 5c 74 65 6d 70 31 00 25 73 5c 74 65 6d 70 32 00 } //1 猥瑜浥ㅰ─屳整灭2
		$a_01_5 = {22 6e 61 6d 65 22 3a 20 22 48 6f 6d 65 20 43 69 6e 65 6d 61 22 } //1 "name": "Home Cinema"
		$a_01_6 = {61 67 65 61 67 6c 62 68 6c 6d 63 6a 69 70 6f 6a 65 6c 66 69 63 6e 6e 6d 66 6d 63 6e 6a 65 6f 6f } //1 ageaglbhlmcjipojelficnnmfmcnjeoo
		$a_01_7 = {4d 49 49 42 49 6a 41 4e 42 67 6b 71 68 6b 69 47 39 77 30 42 41 51 45 46 41 41 4f 43 41 51 38 41 4d 49 49 42 43 67 4b 43 41 51 } //1 MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQ
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=12
 
}