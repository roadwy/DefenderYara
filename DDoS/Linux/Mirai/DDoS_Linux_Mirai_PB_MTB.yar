
rule DDoS_Linux_Mirai_PB_MTB{
	meta:
		description = "DDoS:Linux/Mirai.PB!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_00_0 = {5b 68 74 74 70 20 66 6c 6f 6f 64 5d } //1 [http flood]
		$a_00_1 = {48 65 6c 6c 49 6e 53 69 64 65 } //1 HellInSide
		$a_00_2 = {5b 6b 69 6c 6c 65 72 2d 6b 69 6c 6c 2d 62 79 2d 6e 61 6d 65 5d } //1 [killer-kill-by-name]
		$a_00_3 = {61 74 74 61 63 6b 5f 6d 65 74 68 6f 64 5f 75 64 70 67 65 6e 65 72 69 63 } //1 attack_method_udpgeneric
		$a_00_4 = {61 74 74 61 63 6b 5f 6b 69 6c 6c 5f 61 6c 6c } //1 attack_kill_all
		$a_00_5 = {6b 69 6c 6c 64 69 72 65 63 74 6f 72 69 65 73 } //1 killdirectories
		$a_00_6 = {74 65 61 72 69 6e 67 20 64 6f 77 6e 20 63 6f 6e 6e 65 63 74 69 6f 6e 20 74 6f 20 63 6e 63 } //1 tearing down connection to cnc
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=7
 
}