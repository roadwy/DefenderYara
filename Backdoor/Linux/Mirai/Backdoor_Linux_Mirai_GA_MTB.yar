
rule Backdoor_Linux_Mirai_GA_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.GA!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,07 00 07 00 04 00 00 "
		
	strings :
		$a_00_0 = {74 6d 70 2f 63 6f 6e 64 69 6e 65 74 77 6f 72 6b } //5 tmp/condinetwork
		$a_00_1 = {63 6f 6e 64 69 62 6f 74 } //1 condibot
		$a_00_2 = {76 61 72 2f 7a 78 63 72 39 39 39 39 } //1 var/zxcr9999
		$a_00_3 = {74 72 79 74 6f 63 72 61 63 6b } //1 trytocrack
	condition:
		((#a_00_0  & 1)*5+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=7
 
}