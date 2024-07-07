
rule Trojan_BAT_DiscordRAT_RDA_MTB{
	meta:
		description = "Trojan:BAT/DiscordRAT.RDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {63 63 31 32 32 35 38 66 2d 61 66 32 34 2d 34 37 37 33 2d 61 38 65 33 2d 34 35 64 33 36 35 62 63 62 64 65 39 } //1 cc12258f-af24-4773-a8e3-45d365bcbde9
		$a_01_1 = {44 69 73 63 6f 72 64 20 72 61 74 } //1 Discord rat
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}