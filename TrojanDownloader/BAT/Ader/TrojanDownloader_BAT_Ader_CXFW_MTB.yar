
rule TrojanDownloader_BAT_Ader_CXFW_MTB{
	meta:
		description = "TrojanDownloader:BAT/Ader.CXFW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 73 3a 2f 2f 63 64 6e 2e 64 69 73 63 6f 72 64 61 70 70 2e 63 6f 6d 2f 61 74 74 61 63 68 6d 65 6e 74 73 2f 31 31 30 34 35 30 34 35 37 36 39 31 34 32 34 33 36 32 35 2f 31 31 31 34 33 30 37 32 39 34 30 34 32 32 37 35 38 37 30 2f 4f 72 69 6f 6e 53 74 61 72 74 65 72 2e 64 6c 6c } //1 https://cdn.discordapp.com/attachments/1104504576914243625/1114307294042275870/OrionStarter.dll
		$a_01_1 = {68 74 74 70 73 3a 2f 2f 70 61 73 74 65 62 69 6e 2e 63 6f 6d 2f 48 50 32 59 34 5a 65 7a } //1 https://pastebin.com/HP2Y4Zez
		$a_01_2 = {44 65 73 74 69 6e 61 74 69 6f 6e 20 64 75 20 6a 65 75 20 6e 6f 6e 20 76 61 6c 69 64 65 } //1 Destination du jeu non valide
		$a_01_3 = {4e 27 75 74 69 6c 69 73 65 7a 20 70 61 73 20 64 65 20 70 61 6b 73 20 6d 6f 64 69 66 69 } //1 N'utilisez pas de paks modifi
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}