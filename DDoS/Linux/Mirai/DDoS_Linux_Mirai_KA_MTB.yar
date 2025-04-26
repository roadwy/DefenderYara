
rule DDoS_Linux_Mirai_KA_MTB{
	meta:
		description = "DDoS:Linux/Mirai.KA!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_03_0 = {05 00 1c 3c ?? ?? 9c 27 21 e0 99 03 e0 ff bd 27 1c 00 bf af 18 00 b0 af 10 00 bc af 52 10 02 24 0c 00 00 00 ?? ?? 99 8f 06 00 e0 10 21 80 40 00 09 f8 20 03 00 00 00 00 10 00 bc 8f 00 00 50 ac ff ff 02 24 1c 00 bf 8f 18 00 b0 8f 08 00 e0 03 20 00 bd 27 } //2
		$a_01_1 = {6d 61 69 6e 5f 69 6e 73 74 61 6e 63 65 5f 6b 69 6c 6c } //1 main_instance_kill
		$a_01_2 = {61 74 74 61 63 6b 5f 6d 65 74 68 6f 64 5f 75 64 70 66 6c 6f 6f 64 } //1 attack_method_udpflood
		$a_01_3 = {61 74 74 61 63 6b 5f 6d 65 74 68 6f 64 5f 74 63 70 66 6c 6f 6f 64 } //1 attack_method_tcpflood
		$a_01_4 = {61 74 74 61 63 6b 5f 66 72 65 65 } //1 attack_free
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}