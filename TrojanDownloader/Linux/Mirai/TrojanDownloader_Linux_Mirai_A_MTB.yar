
rule TrojanDownloader_Linux_Mirai_A_MTB{
	meta:
		description = "TrojanDownloader:Linux/Mirai.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {4d 49 52 41 49 0a 00 00 } //02 00 
		$a_02_1 = {4e 49 46 0a 00 00 00 00 47 45 54 20 2f 62 69 6e 73 2f 6d 69 72 61 69 2e 90 02 05 20 48 54 54 50 2f 31 2e 30 0d 0a 0d 0a 00 00 00 00 46 49 4e 0a 00 90 00 } //00 00 
		$a_00_2 = {5d 04 } //00 00 
	condition:
		any of ($a_*)
 
}