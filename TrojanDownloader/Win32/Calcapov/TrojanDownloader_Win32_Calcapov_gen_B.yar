
rule TrojanDownloader_Win32_Calcapov_gen_B{
	meta:
		description = "TrojanDownloader:Win32/Calcapov.gen!B,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_03_0 = {84 c9 74 13 8b d7 2b d0 80 e9 ?? 46 88 0c 02 8a 48 01 40 84 c9 75 f1 } //3
		$a_01_1 = {2e 64 6c 6c 00 53 74 61 72 74 00 } //1
		$a_01_2 = {44 65 6c 65 74 65 55 72 6c 43 61 63 68 65 } //1 DeleteUrlCache
		$a_01_3 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c } //1 URLDownloadToFil
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}