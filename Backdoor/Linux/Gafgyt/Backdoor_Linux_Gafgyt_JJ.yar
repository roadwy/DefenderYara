
rule Backdoor_Linux_Gafgyt_JJ{
	meta:
		description = "Backdoor:Linux/Gafgyt.JJ,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 04 00 00 "
		
	strings :
		$a_03_0 = {37 9e 02 3c b9 79 42 34 21 18 62 00 18 80 82 8f 00 00 00 00 [0-02] 42 24 04 00 43 ac 18 00 c3 8f 6e 3c 02 3c 72 f3 42 34 } //1
		$a_03_1 = {3c 02 9e 37 34 42 79 b9 00 62 18 21 8f 82 80 18 00 00 00 00 24 42 [0-02] ac 43 00 04 8f c3 00 18 3c 02 3c 6e 34 42 f3 72 } //1
		$a_01_2 = {26 18 a2 00 08 00 c2 8f 00 00 00 00 26 18 62 00 37 9e 02 3c b9 79 42 34 26 20 62 00 } //1
		$a_01_3 = {00 a2 18 26 8f c2 00 08 00 00 00 00 00 62 18 26 3c 02 9e 37 34 42 79 b9 00 62 20 26 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=2
 
}