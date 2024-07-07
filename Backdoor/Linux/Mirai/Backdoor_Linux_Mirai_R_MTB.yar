
rule Backdoor_Linux_Mirai_R_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.R!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {8b 19 89 d0 01 d8 89 eb 30 18 89 d0 8b 19 01 d8 89 fb 30 18 89 d0 8b 19 01 d8 89 f3 30 18 89 d0 8b 19 42 01 d8 8a 1c 24 30 18 8b 41 04 25 ff ff 00 00 39 d0 7f ca } //1
		$a_00_1 = {72 6d 20 2d 72 66 20 6e 69 67 } //1 rm -rf nig
		$a_03_2 = {77 67 65 74 20 68 74 74 70 90 02 20 2f 62 69 6e 73 2f 90 02 20 20 2d 4f 20 6e 69 67 90 00 } //1
		$a_00_3 = {63 68 6d 6f 64 20 37 37 37 20 6e 69 67 } //1 chmod 777 nig
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_03_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}