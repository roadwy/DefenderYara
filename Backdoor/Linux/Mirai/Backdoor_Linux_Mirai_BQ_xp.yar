
rule Backdoor_Linux_Mirai_BQ_xp{
	meta:
		description = "Backdoor:Linux/Mirai.BQ!xp,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_01_0 = {52 4f 43 52 59 53 59 52 43 } //2 ROCRYSYRC
		$a_01_1 = {6e 70 78 78 6f 75 64 69 66 66 65 65 67 67 61 61 63 73 63 73 } //1 npxxoudiffeeggaacscs
		$a_01_2 = {68 6c 4c 6a 7a 74 71 5a } //1 hlLjztqZ
		$a_01_3 = {6b 6b 76 65 74 74 67 61 61 61 73 65 63 6e 6e 61 61 61 61 } //1 kkvettgaaasecnnaaaa
		$a_01_4 = {31 30 37 2e 31 37 34 2e 32 34 31 2e 32 30 39 } //1 107.174.241.209
		$a_01_5 = {68 6b 6a 6d 6c 6f 6e 61 } //1 hkjmlona
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=5
 
}