
rule TrojanDownloader_O97M_Obfuse_PBE_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.PBE!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 07 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 6f 72 64 69 6e 61 74 65 75 72 2e 6f 67 69 76 61 72 74 2e 75 73 2f 65 64 69 74 6f 72 2f 51 70 6f 37 4f 41 4f 6e 62 65 2f } //4 http://ordinateur.ogivart.us/editor/Qpo7OAOnbe/
		$a_01_1 = {68 74 74 70 3a 2f 2f 6f 6c 64 2e 6c 69 63 65 75 6d 39 2e 72 75 2f 69 6d 61 67 65 73 2f 30 2f } //4 http://old.liceum9.ru/images/0/
		$a_01_2 = {68 74 74 70 3a 2f 2f 6f 73 74 61 64 73 61 72 6d 61 2e 63 6f 6d 2f 77 70 2d 61 64 6d 69 6e 2f 70 59 6b 36 34 48 68 33 7a 35 68 6a 6e 4d 7a 69 5a 2f } //4 http://ostadsarma.com/wp-admin/pYk64Hh3z5hjnMziZ/
		$a_01_3 = {68 74 74 70 3a 2f 2f 77 77 77 2e 63 75 6e 65 79 74 6b 6f 63 61 73 2e 63 6f 6d 2f 77 70 2d 63 6f 6e 74 65 6e 74 2f 56 53 6e 6f 66 70 45 53 31 77 4f 32 43 63 56 6f 62 2f } //4 http://www.cuneytkocas.com/wp-content/VSnofpES1wO2CcVob/
		$a_01_4 = {68 74 74 70 3a 2f 2f 74 6f 77 61 72 64 73 75 6e 2e 6e 65 74 2f 61 64 6d 69 6e 2f 42 59 47 47 6b 72 59 41 6e 54 2f } //4 http://towardsun.net/admin/BYGGkrYAnT/
		$a_01_5 = {68 74 74 70 3a 2f 2f 6b 2d 61 6e 74 69 71 75 65 73 2e 6a 70 2f 77 70 2d 69 6e 63 6c 75 64 65 73 2f 53 43 59 64 41 36 54 4c 6f 68 59 6b 32 2f } //4 http://k-antiques.jp/wp-includes/SCYdA6TLohYk2/
		$a_01_6 = {44 22 26 22 6c 22 26 22 6c 52 22 26 22 65 67 69 73 74 65 72 22 26 22 53 65 72 76 65 22 26 22 72 } //1 D"&"l"&"lR"&"egister"&"Serve"&"r
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*4+(#a_01_2  & 1)*4+(#a_01_3  & 1)*4+(#a_01_4  & 1)*4+(#a_01_5  & 1)*4+(#a_01_6  & 1)*1) >=5
 
}