
rule TrojanDownloader_BAT_AsyncRat_CCJR_MTB{
	meta:
		description = "TrojanDownloader:BAT/AsyncRat.CCJR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_03_0 = {08 06 07 28 ?? 01 00 0a 16 6f ?? 01 00 0a 13 07 12 07 28 ?? 01 00 0a 6f ?? 01 00 0a 07 11 06 12 01 28 ?? 01 00 0a 2d d8 } //5
		$a_01_1 = {53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 52 00 75 00 6e 00 } //1 SOFTWARE\Microsoft\Windows\CurrentVersion\Run
		$a_01_2 = {53 00 65 00 6c 00 65 00 63 00 74 00 20 00 2a 00 20 00 66 00 72 00 6f 00 6d 00 20 00 41 00 6e 00 74 00 69 00 76 00 69 00 72 00 75 00 73 00 50 00 72 00 6f 00 64 00 75 00 63 00 74 00 } //1 Select * from AntivirusProduct
		$a_01_3 = {52 00 75 00 6e 00 42 00 6f 00 74 00 4b 00 69 00 6c 00 6c 00 65 00 72 00 } //1 RunBotKiller
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=8
 
}