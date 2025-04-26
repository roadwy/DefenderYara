
rule TrojanDownloader_BAT_AgentTesla_NS_MTB{
	meta:
		description = "TrojanDownloader:BAT/AgentTesla.NS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 05 00 00 "
		
	strings :
		$a_81_0 = {63 64 6e 2e 64 69 73 63 6f 72 64 61 70 70 2e 63 6f 6d 2f 61 74 74 61 63 68 6d 65 6e 74 73 2f } //10 cdn.discordapp.com/attachments/
		$a_81_1 = {4b 68 64 6a 76 77 6a 64 74 71 72 79 6d 6d 71 62 75 64 70 2e 5a 73 6e 6d 64 76 69 65 77 73 77 73 66 6f 6a 6b 73 } //1 Khdjvwjdtqrymmqbudp.Zsnmdviewswsfojks
		$a_81_2 = {46 7a 7a 79 68 6a 6c 78 6d 61 74 72 61 67 74 74 70 72 76 6a 71 79 78 2e 4c 6e 79 64 6a 6e 6c 6e 72 64 67 6e 6f 6c 6e 61 6f } //1 Fzzyhjlxmatragttprvjqyx.Lnydjnlnrdgnolnao
		$a_81_3 = {52 65 71 77 67 64 61 6c 63 6b 6c 6a 74 76 67 77 6a 74 6a 77 65 78 61 78 2e 41 61 6d 74 76 73 78 71 65 62 } //1 Reqwgdalckljtvgwjtjwexax.Aamtvsxqeb
		$a_81_4 = {54 6f 61 69 72 62 6e 77 6d 6f 6b 73 61 72 6a 65 78 6a 2e 56 66 69 6f 7a 73 72 74 74 78 68 66 6a 65 6c 76 66 70 69 77 6c 74 78 } //1 Toairbnwmoksarjexj.Vfiozsrttxhfjelvfpiwltx
	condition:
		((#a_81_0  & 1)*10+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=11
 
}