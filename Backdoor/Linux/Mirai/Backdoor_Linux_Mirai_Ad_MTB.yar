
rule Backdoor_Linux_Mirai_Ad_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.Ad!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {63 61 6e 73 63 61 6e } //1 canscan
		$a_00_1 = {6b 69 6c 6c 61 6c 6c 62 6f 74 73 } //1 killallbots
		$a_00_2 = {69 6d 61 67 69 6e 65 20 74 68 72 65 61 64 69 6e 67 20 75 72 20 62 6f 74 73 20 73 6d 68 } //1 imagine threading ur bots smh
		$a_00_3 = {2f 75 64 70 70 6c 61 69 6e } //1 /udpplain
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}