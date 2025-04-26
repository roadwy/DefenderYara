
rule TrojanDownloader_BAT_Bladabindi_I{
	meta:
		description = "TrojanDownloader:BAT/Bladabindi.I,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 "
		
	strings :
		$a_01_0 = {70 00 61 00 73 00 74 00 65 00 62 00 69 00 6e 00 2e 00 63 00 6f 00 6d 00 2f 00 64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 2e 00 70 00 68 00 70 00 3f 00 69 00 3d 00 } //5 pastebin.com/download.php?i=
		$a_01_1 = {70 65 70 73 69 4b 4f 4f } //5 pepsiKOO
		$a_01_2 = {5c 00 41 00 56 00 49 00 52 00 41 00 2e 00 65 00 78 00 65 00 } //1 \AVIRA.exe
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*1) >=11
 
}