
rule TrojanDownloader_BAT_AsyncRat_CCHZ_MTB{
	meta:
		description = "TrojanDownloader:BAT/AsyncRat.CCHZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {13 14 11 14 6f ?? 00 00 0a 26 73 ?? ?? ?? ?? 13 15 11 15 72 ?? 06 00 70 73 ?? ?? ?? 0a 06 07 28 ?? 00 00 0a 6f ?? 00 00 0a 00 73 ?? 00 00 0a 13 16 11 16 72 } //1
		$a_01_1 = {44 00 69 00 73 00 61 00 62 00 6c 00 65 00 43 00 4d 00 44 00 } //1 DisableCMD
		$a_01_2 = {53 00 69 00 64 00 65 00 6c 00 6f 00 61 00 64 00 } //1 Sideload
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}