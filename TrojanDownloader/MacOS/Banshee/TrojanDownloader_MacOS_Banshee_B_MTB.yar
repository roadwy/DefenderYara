
rule TrojanDownloader_MacOS_Banshee_B_MTB{
	meta:
		description = "TrojanDownloader:MacOS/Banshee.B!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {00 00 00 90 00 80 3d 91 dc 00 00 94 e1 a3 00 91 e0 03 14 aa 02 00 80 52 de 00 00 94 e8 01 80 52 e8 2b 00 b9 e8 2b 40 b9 1f 4d 00 71 } //1
		$a_01_1 = {88 0d 80 52 e8 63 00 39 08 00 00 90 08 39 3c 91 08 01 40 f9 e8 0b 00 f9 73 02 40 f9 f4 a3 00 91 e8 a3 00 91 e0 43 00 91 65 00 00 94 e8 ff c0 39 e9 17 40 f9 1f 01 00 71 28 b1 94 9a e8 7f 00 a9 e0 03 13 aa e1 03 13 aa 9b 00 00 94 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}