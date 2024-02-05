
rule TrojanDownloader_Linux_Mirai_AN{
	meta:
		description = "TrojanDownloader:Linux/Mirai.AN,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {55 73 65 72 2d 41 67 65 6e 74 3a 20 44 61 72 6b } //01 00 
		$a_02_1 = {63 64 20 2f 74 6d 70 3b 20 77 67 65 74 20 68 74 74 70 3a 2f 2f 90 02 28 2e 73 68 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}