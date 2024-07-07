
rule Trojan_BAT_DCRat_MBC_MTB{
	meta:
		description = "Trojan:BAT/DCRat.MBC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {54 67 46 52 56 7a 67 48 59 61 6d 68 35 68 71 51 6a 4a 74 33 4b } //1 TgFRVzgHYamh5hqQjJt3K
		$a_01_1 = {5a 56 62 4d 42 75 78 36 51 64 6e 4d 72 74 48 54 33 31 32 4c 58 64 79 75 36 62 6b 45 43 47 42 6a 69 51 47 68 42 74 77 57 76 77 } //1 ZVbMBux6QdnMrtHT312LXdyu6bkECGBjiQGhBtwWvw
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}