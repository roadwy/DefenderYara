
rule Backdoor_Linux_Mirai_C{
	meta:
		description = "Backdoor:Linux/Mirai.C,SIGNATURE_TYPE_ELFHSTR_EXT,07 00 07 00 04 00 00 "
		
	strings :
		$a_02_0 = {63 64 20 2f 6d 6e 74 20 7c 7c 20 63 64 20 2f 72 6f 6f 74 20 7c 7c 20 63 64 20 2f 3b 20 77 67 65 74 20 68 74 74 70 3a 2f 2f [0-03] 2e [0-03] 2e [0-03] 2e [0-03] 2f 62 69 6e 73 2e 73 68 3b } //5
		$a_02_1 = {63 64 20 2f 6d 6e 74 20 7c 7c 20 63 64 20 2f 72 6f 6f 74 20 7c 7c 20 63 64 20 2f 3b 20 77 67 65 74 20 68 74 74 70 3a 2f 2f [0-03] 2e [0-03] 2e [0-03] 2e [0-03] 2f 53 77 61 67 2e 73 68 3b } //5
		$a_01_2 = {42 6f 74 20 64 65 70 6c 6f 79 20 73 75 63 63 65 73 73 } //1 Bot deploy success
		$a_01_3 = {42 6f 74 20 64 65 70 6c 6f 79 20 66 61 69 6c 65 64 } //1 Bot deploy failed
	condition:
		((#a_02_0  & 1)*5+(#a_02_1  & 1)*5+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=7
 
}