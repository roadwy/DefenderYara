
rule TrojanDownloader_O97M_Qakbot_GRB_MTB{
	meta:
		description = "TrojanDownloader:O97M/Qakbot.GRB!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 77 77 77 2e 6e 6f 77 65 6d 69 61 73 74 65 63 7a 6b 6f 2e 70 6c 2f 63 69 67 70 6e 64 72 6f 7a 68 6d 2f } //1 http://www.nowemiasteczko.pl/cigpndrozhm/
		$a_01_1 = {43 3a 5c 47 72 61 76 69 74 79 5c 47 72 61 76 69 74 79 32 5c 46 69 6b 73 61 74 2e 65 78 65 } //1 C:\Gravity\Gravity2\Fiksat.exe
		$a_01_2 = {43 72 65 61 74 65 44 69 72 65 63 74 6f 72 79 41 } //1 CreateDirectoryA
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}