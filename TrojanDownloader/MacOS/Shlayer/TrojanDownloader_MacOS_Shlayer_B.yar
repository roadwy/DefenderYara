
rule TrojanDownloader_MacOS_Shlayer_B{
	meta:
		description = "TrojanDownloader:MacOS/Shlayer.B,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {80 f1 7a 88 4c 07 1b 50 58 50 58 90 50 58 48 ff c8 48 83 f8 fc 75 } //1
		$a_01_1 = {a1 33 10 d2 57 00 b1 33 20 00 00 d1 33 23 e5 59 00 f4 33 0b } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}