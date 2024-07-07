
rule Trojan_BAT_Disstl_SA_MTB{
	meta:
		description = "Trojan:BAT/Disstl.SA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_80_0 = {44 6f 77 6e 6c 6f 61 64 46 69 6c 65 } //DownloadFile  1
		$a_80_1 = {68 74 74 70 73 3a 2f 2f 63 61 6e 61 72 79 2e 64 69 73 63 6f 72 64 2e 63 6f 6d 2f 61 70 69 2f 77 65 62 68 6f 6f 6b 73 2f } //https://canary.discord.com/api/webhooks/  1
		$a_80_2 = {68 74 74 70 73 3a 2f 2f 63 64 6e 2e 64 69 73 63 6f 72 64 61 70 70 2e 63 6f 6d 2f } //https://cdn.discordapp.com/  1
		$a_80_3 = {68 74 74 70 3a 2f 2f 73 66 33 71 32 77 72 71 33 34 2e 64 64 6e 73 2e 6e 65 74 } //http://sf3q2wrq34.ddns.net  1
		$a_80_4 = {47 61 74 6f 6e 46 69 6c 65 73 } //GatonFiles  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=5
 
}