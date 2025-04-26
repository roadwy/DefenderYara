
rule Backdoor_Linux_Gafgyt_AS_MTB{
	meta:
		description = "Backdoor:Linux/Gafgyt.AS!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,08 00 08 00 05 00 00 "
		
	strings :
		$a_02_0 = {63 64 20 2f 74 6d 70 20 7c 7c 20 63 64 20 2f 76 61 72 2f 72 75 6e 3b 77 67 65 74 20 68 74 74 70 3a 2f 2f [0-15] 2f [0-10] 3b 73 68 20 [0-10] 3b 72 6d 20 [0-10] 3b 74 66 74 70 20 2d 72 20 [0-10] 20 2d 67 20 [0-20] 3b 63 68 6d 6f 64 20 37 37 37 } //5
		$a_01_1 = {53 43 41 4e 5a 45 52 20 4f 4e 20 7c 20 4f 46 46 } //1 SCANZER ON | OFF
		$a_01_2 = {4c 4f 4c 4e 4f 47 54 46 4f } //1 LOLNOGTFO
		$a_01_3 = {67 61 79 66 67 74 } //1 gayfgt
		$a_01_4 = {54 45 4c 53 43 41 4e 4e 45 52 } //1 TELSCANNER
	condition:
		((#a_02_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=8
 
}