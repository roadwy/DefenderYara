
rule Backdoor_Linux_Mirai_L_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.L!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 06 00 00 "
		
	strings :
		$a_00_0 = {6b 69 6c 6c 61 6c 6c 62 6f 74 73 } //1 killallbots
		$a_00_1 = {2f 62 69 6e 2f 62 75 73 79 62 6f 78 20 4f 42 4f 54 } //1 /bin/busybox OBOT
		$a_00_2 = {61 74 74 61 63 6b 5f 73 65 6e 64 } //1 attack_send
		$a_00_3 = {6b 69 6c 6c 65 72 5f 73 65 6e 64 62 61 63 6b } //1 killer_sendback
		$a_00_4 = {2f 75 73 72 2f 6c 69 62 2f 70 6f 6c 6b 69 74 2d 31 2f 70 6f 6c 6b 69 74 64 } //1 /usr/lib/polkit-1/polkitd
		$a_00_5 = {2f 62 69 6e 2f 68 67 63 6d 65 67 61 63 6f } //1 /bin/hgcmegaco
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=3
 
}