
rule Trojan_Linux_Flooder_H_MTB{
	meta:
		description = "Trojan:Linux/Flooder.H!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {73 65 6e 64 55 44 50 46 6c 6f 6f 64 } //1 sendUDPFlood
		$a_01_1 = {68 61 6e 64 6c 65 49 50 49 50 41 74 74 61 63 6b } //1 handleIPIPAttack
		$a_01_2 = {6d 61 69 6e 2e 53 65 6e 64 52 61 77 54 43 50 } //1 main.SendRawTCP
		$a_01_3 = {6d 61 69 6e 2e 73 65 6e 64 4d 69 6e 65 63 72 61 66 74 50 61 63 6b 65 74 73 } //1 main.sendMinecraftPackets
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}