
rule TrojanDownloader_O97M_Qakbot_PUE_MTB{
	meta:
		description = "TrojanDownloader:O97M/Qakbot.PUE!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_00_0 = {4a 4a 43 43 43 4a 4a } //1 JJCCCJJ
		$a_00_1 = {4a 4a 43 43 42 42 } //1 JJCCBB
		$a_00_2 = {7a 69 70 66 6c 64 72 } //1 zipfldr
		$a_00_3 = {68 74 74 70 73 3a 2f 2f 79 63 31 6f 70 33 6a 68 33 39 72 2e 78 79 7a 2f 67 75 74 70 61 67 2e 70 68 70 } //1 https://yc1op3jh39r.xyz/gutpag.php
		$a_00_4 = {43 3a 5c 6d 76 6f 72 70 } //1 C:\mvorp
		$a_00_5 = {5c 6f 6f 6a 66 6a 2e 65 78 65 } //1 \oojfj.exe
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=6
 
}