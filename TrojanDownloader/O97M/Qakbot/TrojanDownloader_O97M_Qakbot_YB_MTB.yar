
rule TrojanDownloader_O97M_Qakbot_YB_MTB{
	meta:
		description = "TrojanDownloader:O97M/Qakbot.YB!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 77 77 77 2e 63 72 6c 2d 6c 68 6b 2e 65 75 73 2f 62 62 76 6e 6f 74 69 2f 35 33 30 33 34 30 2e 70 6e 67 } //2 http://www.crl-lhk.eus/bbvnoti/530340.png
		$a_01_1 = {68 74 74 70 73 3a 2f 2f 77 77 77 2e 6e 6f 74 61 6d 75 7a 69 6b 61 6c 65 74 6c 65 72 69 2e 63 6f 6d 2f 31 39 2e 67 69 66 } //2 https://www.notamuzikaletleri.com/19.gif
		$a_01_2 = {43 3a 5c 44 61 74 6f 70 5c } //1 C:\Datop\
		$a_01_3 = {43 3a 5c 57 45 72 74 75 } //1 C:\WErtu
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}