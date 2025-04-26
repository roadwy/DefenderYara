
rule TrojanDownloader_Linux_Kidsoper_A{
	meta:
		description = "TrojanDownloader:Linux/Kidsoper.A,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {42 49 47 44 49 43 4b 4d 53 20 3d 20 45 6e 76 69 72 6f 6e 28 77 74 66 28 22 32 32 40 57 54 46 40 33 39 40 57 54 46 40 34 37 40 57 54 46 40 35 30 22 29 29 } //1 BIGDICKMS = Environ(wtf("22@WTF@39@WTF@47@WTF@50"))
		$a_01_1 = {42 49 47 44 49 43 4b 53 4f 50 48 4f 53 20 3d 20 22 68 74 74 70 3a 2f 2f } //1 BIGDICKSOPHOS = "http://
		$a_01_2 = {42 49 47 44 49 43 4b 4b 41 53 50 45 52 20 3d 20 42 49 47 44 49 43 4b 4b 41 53 50 45 52 20 2b 20 42 49 47 44 49 43 4b 53 4f 50 48 4f 53 } //1 BIGDICKKASPER = BIGDICKKASPER + BIGDICKSOPHOS
		$a_01_3 = {53 68 65 6c 6c 20 42 49 47 44 49 43 4b 4b 41 53 50 45 52 2c 20 76 62 48 69 64 65 } //1 Shell BIGDICKKASPER, vbHide
		$a_01_4 = {61 72 72 20 3d 20 53 70 6c 69 74 28 73 68 69 74 2c 20 22 40 57 54 46 40 22 29 } //1 arr = Split(shit, "@WTF@")
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}