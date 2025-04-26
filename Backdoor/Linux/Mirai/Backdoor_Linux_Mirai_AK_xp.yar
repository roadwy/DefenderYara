
rule Backdoor_Linux_Mirai_AK_xp{
	meta:
		description = "Backdoor:Linux/Mirai.AK!xp,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {64 64 6f 73 5f 66 6c 6f 6f 64 5f 74 63 70 } //2 ddos_flood_tcp
		$a_01_1 = {64 64 6f 73 5f 66 6c 6f 6f 64 5f 75 64 70 } //2 ddos_flood_udp
		$a_01_2 = {72 75 6e 6e 69 6e 67 5f 70 61 72 65 6e 74 73 } //2 running_parents
		$a_01_3 = {6e 70 78 58 6f 75 64 69 66 46 65 45 67 47 61 41 43 53 63 73 } //1 npxXoudifFeEgGaACScs
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1) >=5
 
}