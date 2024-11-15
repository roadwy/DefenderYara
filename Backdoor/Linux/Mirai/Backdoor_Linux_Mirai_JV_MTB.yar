
rule Backdoor_Linux_Mirai_JV_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.JV!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {41 74 74 61 63 6b 55 64 70 52 61 6b 6e 65 74 } //1 AttackUdpRaknet
		$a_01_1 = {61 74 74 61 63 6b 5f 70 61 72 73 65 2e 63 } //1 attack_parse.c
		$a_01_2 = {4e 65 74 77 6f 72 6b 53 65 6e 64 45 6e 63 72 79 70 74 65 64 50 61 63 6b 65 74 } //1 NetworkSendEncryptedPacket
		$a_01_3 = {70 6f 72 74 5f 6b 69 6c 6c 65 72 2e 63 } //1 port_killer.c
		$a_01_4 = {41 74 74 61 63 6b 54 63 70 52 61 77 42 61 73 69 63 } //1 AttackTcpRawBasic
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}