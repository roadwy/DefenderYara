
rule TrojanDownloader_Win32_Banload_ALT{
	meta:
		description = "TrojanDownloader:Win32/Banload.ALT,SIGNATURE_TYPE_PEHSTR_EXT,ffffffde 00 ffffffdd 00 0e 00 00 64 00 "
		
	strings :
		$a_01_0 = {2f 49 6e 73 74 61 6c 2e 62 63 6b 00 } //64 00 
		$a_01_1 = {2f 54 69 6d 65 2e 63 6f 6d 00 } //14 00 
		$a_01_2 = {73 65 67 6b 73 61 32 30 31 34 2e 63 6f 6d } //14 00  segksa2014.com
		$a_01_3 = {65 6d 70 6f 72 69 6f 67 6f 73 70 65 6c 2e 63 6f 6d } //14 00  emporiogospel.com
		$a_01_4 = {70 65 72 73 6f 6e 6e 61 6c 69 74 65 78 63 6c 75 73 69 76 65 68 73 2e 63 6f 6d } //14 00  personnalitexclusivehs.com
		$a_01_5 = {67 72 61 6e 64 65 73 67 69 67 61 73 2e 63 6f 6d } //14 00  grandesgigas.com
		$a_01_6 = {66 61 63 65 62 75 6b 73 63 6f 6e 65 63 74 2e 63 6f 6d } //01 00  facebuksconect.com
		$a_01_7 = {00 4d 65 6e 75 20 49 6e 69 63 69 61 72 00 } //01 00  䴀湥⁵湉捩慩r
		$a_01_8 = {00 a3 ab 96 92 9a d1 9a 87 9a 00 } //01 00 
		$a_01_9 = {43 3a 5c 77 69 6e 64 69 72 5c 74 69 6d 65 } //01 00  C:\windir\time
		$a_01_10 = {2f 69 6e 73 74 61 6c 6c 6c 6f 67 73 2f } //01 00  /installlogs/
		$a_01_11 = {2f 6c 61 73 6c 6f 67 2f } //01 00  /laslog/
		$a_01_12 = {6c 6f 6a 61 2f 6c 6f 74 65 2f } //01 00  loja/lote/
		$a_01_13 = {00 74 69 6d 65 2e 63 6f 6d 00 } //00 00 
	condition:
		any of ($a_*)
 
}