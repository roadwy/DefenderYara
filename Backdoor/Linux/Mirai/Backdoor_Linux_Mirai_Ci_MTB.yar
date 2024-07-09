
rule Backdoor_Linux_Mirai_Ci_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.Ci!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,07 00 07 00 04 00 00 "
		
	strings :
		$a_03_0 = {63 64 20 2f 64 61 74 61 2f 6c 6f 63 61 6c 2f 74 6d 70 3b 20 62 75 73 79 62 6f 78 20 77 67 65 74 20 68 74 74 70 3a 2f 2f [0-15] 2f 77 67 65 74 20 2d 4f } //3
		$a_03_1 = {63 75 72 6c 20 2d 4f 20 68 74 74 70 3a 2f 2f [0-15] 2f 63 75 72 6c 3b 20 73 68 20 63 75 72 6c 3b 20 72 6d } //3
		$a_00_2 = {6b 69 6c 6c 65 64 20 70 69 64 } //1 killed pid
		$a_00_3 = {39 78 73 73 70 6e 76 67 63 38 61 6a 35 70 69 37 6d 32 38 70 } //1 9xsspnvgc8aj5pi7m28p
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*3+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=7
 
}