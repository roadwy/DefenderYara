
rule TrojanDownloader_MacOS_Shlayer_A{
	meta:
		description = "TrojanDownloader:MacOS/Shlayer.A,SIGNATURE_TYPE_MACHOHSTR_EXT,03 00 03 00 04 00 00 03 00 "
		
	strings :
		$a_01_0 = {2f 55 73 65 72 73 2f 61 64 6d 69 6e 2f 77 6f 72 6b 2f 66 63 61 37 62 36 62 61 36 62 38 36 38 38 33 38 } //01 00 
		$a_01_1 = {68 74 74 70 73 3a 2f 2f 65 2e 25 40 } //01 00 
		$a_01_2 = {73 6c 65 65 70 20 25 6c 75 3b 20 6f 70 65 6e 20 22 25 40 22 } //02 00 
		$a_03_3 = {2f 74 6d 70 2f 90 1c 09 00 90 1d 06 00 5f 69 6e 73 74 61 6c 6c 90 00 } //00 00 
		$a_00_4 = {5d 04 } //00 00 
	condition:
		any of ($a_*)
 
}