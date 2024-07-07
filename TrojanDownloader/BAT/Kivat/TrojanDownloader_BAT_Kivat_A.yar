
rule TrojanDownloader_BAT_Kivat_A{
	meta:
		description = "TrojanDownloader:BAT/Kivat.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_80_0 = {62 67 61 73 2e 74 78 74 } //bgas.txt  1
		$a_80_1 = {6a 73 61 73 2e 74 78 74 } //jsas.txt  1
		$a_80_2 = {5c 69 61 63 66 66 6e 64 61 64 63 69 65 63 64 63 6f 70 6f 66 6b 6b 65 67 63 70 63 6d 6e 6a 70 70 68 5c } //\iacffndadciecdcopofkkegcpcmnjpph\  2
		$a_80_3 = {47 f6 72 65 76 20 59 f6 6e 65 74 69 63 69 73 69 20 2d 20 47 6f 6f 67 6c 65 20 43 68 72 6f 6d 65 } //G�rev Y�neticisi - Google Chrome  1
		$a_80_4 = {77 69 6e 75 70 64 61 74 65 72 2e 65 78 65 } //winupdater.exe  2
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*2+(#a_80_3  & 1)*1+(#a_80_4  & 1)*2) >=5
 
}