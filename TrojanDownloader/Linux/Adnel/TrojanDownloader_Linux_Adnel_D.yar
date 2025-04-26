
rule TrojanDownloader_Linux_Adnel_D{
	meta:
		description = "TrojanDownloader:Linux/Adnel.D,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {42 41 52 4e 45 59 20 3d 20 42 41 52 4e 45 59 20 2b 20 42 52 41 4e 44 45 4e 28 4e 55 4d 42 45 52 53 2c 20 42 55 46 4f 52 44 29 } //1 BARNEY = BARNEY + BRANDEN(NUMBERS, BUFORD)
		$a_01_1 = {42 52 41 4e 44 45 4e 20 3d 20 43 68 72 28 4e 55 4d 42 45 52 53 20 58 6f 72 20 42 55 46 4f 52 44 29 } //1 BRANDEN = Chr(NUMBERS Xor BUFORD)
		$a_01_2 = {50 75 62 6c 69 63 20 43 6f 6e 73 74 20 4f 43 54 41 56 49 4f 20 3d 20 22 41 55 47 55 53 54 49 4e 45 59 4f 55 4e 47 } //1 Public Const OCTAVIO = "AUGUSTINEYOUNG
		$a_01_3 = {46 75 6e 63 74 69 6f 6e 20 55 4c 59 53 53 45 53 20 4c 69 62 20 22 77 69 6e 69 6e 65 74 2e 64 6c 6c 22 20 41 6c 69 61 73 20 22 49 6e 74 65 72 6e 65 74 52 65 61 64 46 69 6c 65 22 } //1 Function ULYSSES Lib "wininet.dll" Alias "InternetReadFile"
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}