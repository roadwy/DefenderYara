
rule Trojan_Linux_Winnti_bf_MTB{
	meta:
		description = "Trojan:Linux/Winnti.bf!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,08 00 08 00 09 00 00 "
		
	strings :
		$a_00_0 = {50 53 31 3d 5b 1b 5b 30 3b 33 32 3b 34 30 6d 5c 75 40 5c 68 3a 5c 77 5d 5c 24 } //1
		$a_00_1 = {48 69 64 65 50 69 64 50 6f 72 74 } //1 HidePidPort
		$a_00_2 = {62 79 70 61 73 73 5f 69 70 74 61 62 6c 65 73 } //1 bypass_iptables
		$a_00_3 = {73 63 61 6e 64 69 72 } //1 scandir
		$a_00_4 = {63 6f 6e 66 5f 44 65 6c 41 6c 6c 5f 44 4e 53 } //1 conf_DelAll_DNS
		$a_00_5 = {73 65 6e 64 75 64 70 } //1 sendudp
		$a_00_6 = {68 69 64 65 2e 63 } //1 hide.c
		$a_00_7 = {47 65 74 5f 41 6c 6c 49 50 } //1 Get_AllIP
		$a_00_8 = {43 42 32 46 41 33 36 41 41 41 39 35 34 31 46 30 55 6e 6b 6e 6f 77 6e } //1 CB2FA36AAA9541F0Unknown
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1) >=8
 
}