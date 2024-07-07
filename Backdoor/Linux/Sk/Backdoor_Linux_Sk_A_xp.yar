
rule Backdoor_Linux_Sk_A_xp{
	meta:
		description = "Backdoor:Linux/Sk.A!xp,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 04 00 00 "
		
	strings :
		$a_00_0 = {8b 3c 8e 89 c1 d3 ef 89 f8 8b 55 f4 88 04 13 43 83 fb 07 } //1
		$a_00_1 = {8b 55 10 cd 80 89 85 e8 df ff ff 85 c0 7d 02 } //1
		$a_00_2 = {8b 45 0c 8b 18 89 df 89 c8 49 f2 ae f7 d1 49 8d 74 19 fc bf c0 c8 04 08 } //1
		$a_00_3 = {69 74 3a 20 53 74 61 72 74 69 6e 67 20 62 61 63 6b 64 6f 6f 72 20 } //1 it: Starting backdoor 
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=2
 
}