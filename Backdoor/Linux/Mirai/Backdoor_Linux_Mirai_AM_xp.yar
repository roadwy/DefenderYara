
rule Backdoor_Linux_Mirai_AM_xp{
	meta:
		description = "Backdoor:Linux/Mirai.AM!xp,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {2f 65 74 63 2f 72 65 73 6f 6c 76 2e 63 6f 6e 66 } //1 /etc/resolv.conf
		$a_01_1 = {65 67 76 6e 6d 61 63 6e 6b 72 } //1 egvnmacnkr
		$a_01_2 = {6e 6d 6e 6c 6d 65 76 64 6d } //1 nmnlmevdm
		$a_01_3 = {68 6c 4c 6a 7a 74 71 5a } //1 hlLjztqZ
		$a_01_4 = {6e 70 78 58 6f 75 64 69 66 46 65 45 67 47 61 41 43 53 63 73 } //1 npxXoudifFeEgGaACScs
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}