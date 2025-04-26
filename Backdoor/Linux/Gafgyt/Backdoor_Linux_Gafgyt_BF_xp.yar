
rule Backdoor_Linux_Gafgyt_BF_xp{
	meta:
		description = "Backdoor:Linux/Gafgyt.BF!xp,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {2f 65 74 63 2f 64 72 6f 70 62 65 61 72 2f } //2 /etc/dropbear/
		$a_01_1 = {62 4f 61 54 6e 45 74 20 73 79 73 74 65 6d } //2 bOaTnEt system
		$a_01_2 = {6e 70 78 58 6f 75 64 69 66 46 65 45 67 47 61 41 43 53 63 73 } //1 npxXoudifFeEgGaACScs
		$a_01_3 = {68 6c 4c 6a 7a 74 71 5a } //1 hlLjztqZ
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}