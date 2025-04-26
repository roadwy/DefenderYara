
rule TrojanDownloader_Win32_Dadon_A{
	meta:
		description = "TrojanDownloader:Win32/Dadon.A,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {4e 00 40 00 46 00 46 00 42 00 41 00 46 00 46 00 42 00 41 00 46 00 46 00 46 00 41 00 46 00 46 00 4c 00 45 00 46 00 46 00 49 00 44 00 46 00 46 00 49 00 44 00 46 00 46 00 } //1 N@FFBAFFBAFFFAFFLEFFIDFFIDFF
		$a_01_1 = {44 65 6c 65 74 65 55 72 6c 43 61 63 68 65 45 6e 74 72 79 } //1 DeleteUrlCacheEntry
		$a_01_2 = {73 00 6e 00 69 00 66 00 66 00 } //1 sniff
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}