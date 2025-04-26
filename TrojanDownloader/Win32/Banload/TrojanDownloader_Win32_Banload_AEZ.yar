
rule TrojanDownloader_Win32_Banload_AEZ{
	meta:
		description = "TrojanDownloader:Win32/Banload.AEZ,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {42 69 74 42 74 6e 31 43 6c 69 63 6b } //1 BitBtn1Click
		$a_01_1 = {4e 6f 76 69 64 61 64 65 } //1 Novidade
		$a_01_2 = {68 74 74 70 3a 2f 2f 77 77 77 2e 63 6f 61 6c 61 6f 6e 6c 69 6e 65 2e 63 6f 6d } //3 http://www.coalaonline.com
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*3) >=5
 
}