
rule Backdoor_Linux_Mirai_AS_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.AS!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 05 00 00 "
		
	strings :
		$a_00_0 = {78 6d 61 73 61 74 74 61 63 6b } //1 xmasattack
		$a_00_1 = {69 63 6d 70 61 74 74 61 63 6b } //1 icmpattack
		$a_00_2 = {67 61 6d 65 61 74 74 61 63 6b } //1 gameattack
		$a_00_3 = {75 64 70 76 73 65 61 74 74 61 63 6b } //1 udpvseattack
		$a_00_4 = {74 63 70 61 74 74 61 63 6b } //1 tcpattack
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=3
 
}