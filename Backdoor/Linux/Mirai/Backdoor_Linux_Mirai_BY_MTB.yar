
rule Backdoor_Linux_Mirai_BY_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.BY!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {62 75 73 79 62 6f 78 20 77 67 65 74 20 2d 67 [0-18] 2d 6c 20 2f 74 6d 70 2f 62 69 67 48 20 2d 72 20 2f 6d 69 70 73 } //1
		$a_03_1 = {63 68 6d 6f 64 20 37 37 37 20 2f 74 6d 70 2f 62 69 67 48 3b 2f 74 6d 70 2f 62 69 67 48 20 [0-08] 2e 72 65 70 } //1
		$a_00_2 = {72 6d 20 2d 72 66 20 2f 74 6d 70 2f 62 69 67 48 } //1 rm -rf /tmp/bigH
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}