
rule TrojanDownloader_O97M_Trickbot_AT_MTB{
	meta:
		description = "TrojanDownloader:O97M/Trickbot.AT!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {41 74 74 72 69 62 75 74 65 20 56 42 5f 4e 61 6d 65 20 3d 20 22 61 70 70 74 69 63 6b 22 } //1 Attribute VB_Name = "apptick"
		$a_01_1 = {57 73 68 53 68 65 6c 6c 0d 0a 20 20 20 20 57 69 6e 5a 69 70 2e 45 78 65 63 20 22 65 78 70 6c 6f 72 65 72 20 63 3a 5c 45 61 72 74 68 5c 43 6f 6e 76 65 72 74 53 68 6f 72 74 2e 76 62 65 } //1
		$a_01_2 = {52 65 76 65 72 73 65 20 74 68 65 20 43 61 72 64 4e 75 6d 62 65 72 } //1 Reverse the CardNumber
		$a_01_3 = {28 44 69 67 69 74 20 2a 20 28 31 20 2b 20 28 58 20 2d 20 31 29 20 4d 6f 64 20 32 29 29 } //1 (Digit * (1 + (X - 1) Mod 2))
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}