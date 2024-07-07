
rule TrojanDownloader_BAT_Banload_R{
	meta:
		description = "TrojanDownloader:BAT/Banload.R,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {54 63 6f 30 33 2e 65 78 65 } //1 Tco03.exe
		$a_01_1 = {2e 00 65 00 78 00 65 00 00 23 77 00 77 00 77 00 2e 00 67 00 6f 00 6f 00 67 00 6c 00 65 00 2e 00 63 00 6f 00 6d 00 2e 00 62 00 72 } //1
		$a_01_2 = {43 00 3a 00 5c 00 61 00 72 00 71 00 54 00 65 00 78 00 74 00 2e 00 74 00 78 00 74 00 } //1 C:\arqText.txt
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}