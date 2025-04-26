
rule Backdoor_Linux_Mirai_P_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.P!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_00_0 = {54 53 6f 75 72 63 65 20 45 6e 67 69 6e 65 20 51 75 65 72 79 } //1 TSource Engine Query
		$a_00_1 = {68 74 74 70 66 6c 6f 6f 64 } //1 httpflood
		$a_01_2 = {6c 6f 6c 6e 6f 67 74 66 6f } //1 lolnogtfo
		$a_00_3 = {75 64 70 70 6c 61 69 6e } //1 udpplain
		$a_00_4 = {37 75 6a 4d 6b 6f 30 61 64 6d 69 6e } //1 7ujMko0admin
		$a_00_5 = {68 75 6e 74 35 37 35 39 } //1 hunt5759
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_01_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=5
 
}
rule Backdoor_Linux_Mirai_P_MTB_2{
	meta:
		description = "Backdoor:Linux/Mirai.P!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {8b 19 89 d0 01 d8 89 eb 30 18 89 d0 8b 19 01 d8 89 fb 30 18 89 d0 8b 19 01 d8 89 f3 30 18 89 d0 8b 19 42 01 d8 8a 1c 24 30 18 8b 41 04 25 ff ff 00 00 39 d0 7f ca } //1
		$a_03_1 = {2f 62 69 6e 2f 62 75 73 79 62 6f 78 20 77 67 65 74 20 2d 67 [0-20] 2d 6c 20 2f 74 6d 70 2f [0-10] 20 2d 72 } //1
		$a_00_2 = {2f 62 69 6e 2f 62 75 73 79 62 6f 78 20 63 68 6d 6f 64 20 37 37 37 20 2a 20 2f 74 6d 70 2f } //1 /bin/busybox chmod 777 * /tmp/
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}