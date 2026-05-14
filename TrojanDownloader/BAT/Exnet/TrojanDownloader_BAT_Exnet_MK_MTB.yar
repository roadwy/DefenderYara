
rule TrojanDownloader_BAT_Exnet_MK_MTB{
	meta:
		description = "TrojanDownloader:BAT/Exnet.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,23 00 23 00 02 00 00 "
		
	strings :
		$a_01_0 = {73 1e 00 00 0a 13 0c 11 0c 11 0b 6f 1f 00 00 0a 13 0d 11 0d 28 03 00 00 06 13 0e 11 0e 28 20 00 00 0a 13 0f 11 0f 6f 21 00 00 0a 13 10 11 10 6f 22 00 00 0a 8e 69 3a 06 00 00 00 14 38 0e 00 00 00 17 8d 01 00 00 1b } //25
		$a_81_1 = {51 59 65 78 76 7a 33 66 4c 65 64 41 7a 43 30 61 36 41 39 34 2b 2f 58 6f 55 2b 54 6d 31 72 62 79 58 6a 64 47 36 47 37 72 6d 6b 42 45 79 76 30 31 68 53 63 53 62 75 47 5a 65 45 46 4e 49 49 38 77 } //10 QYexvz3fLedAzC0a6A94+/XoU+Tm1rbyXjdG6G7rmkBEyv01hScSbuGZeEFNII8w
	condition:
		((#a_01_0  & 1)*25+(#a_81_1  & 1)*10) >=35
 
}