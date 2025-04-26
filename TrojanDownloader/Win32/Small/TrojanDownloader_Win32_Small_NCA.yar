
rule TrojanDownloader_Win32_Small_NCA{
	meta:
		description = "TrojanDownloader:Win32/Small.NCA,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {0f 84 84 00 00 00 48 74 5e 48 74 4c 48 74 3a 48 74 28 48 74 16 48 0f } //1
		$a_01_1 = {53 8b 5c 24 0c 56 57 6a 40 33 c0 33 f6 39 74 24 1c 59 8b fb f3 ab 7e 19 8b 7c 24 10 33 c0 8a 07 47 50 e8 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}