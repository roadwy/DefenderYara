
rule Backdoor_Linux_Mirai_BJ_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.BJ!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 05 00 00 "
		
	strings :
		$a_00_0 = {8b 19 89 d0 01 d8 89 eb 30 18 89 d0 8b 19 01 d8 89 fb 30 18 89 d0 8b 19 01 d8 89 f3 30 18 89 d0 8b 19 42 01 d8 8a 1c 24 30 18 8b 41 04 25 ff ff 00 00 39 d0 7f ca } //1
		$a_00_1 = {6e 70 78 58 6f 75 64 69 66 46 65 45 67 47 61 41 43 53 63 73 } //1 npxXoudifFeEgGaACScs
		$a_00_2 = {6f 64 30 32 39 65 6a 73 6c 6b 77 6e 32 38 64 39 32 6c 73 30 32 70 77 6c 32 30 64 67 71 6e 77 } //1 od029ejslkwn28d92ls02pwl20dgqnw
		$a_00_3 = {65 67 76 6e 6d 61 63 6e 6b 72 } //1 egvnmacnkr
		$a_00_4 = {68 6c 4c 6a 7a 74 71 5a } //1 hlLjztqZ
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=3
 
}