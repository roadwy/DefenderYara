
rule Backdoor_Linux_Gafgyt_AT_MTB{
	meta:
		description = "Backdoor:Linux/Gafgyt.AT!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_02_0 = {63 64 20 2f 74 6d 70 3b 20 77 67 65 74 20 68 74 74 70 3a 2f 2f [0-15] 2f [0-10] 2f [0-10] 3b 20 63 68 6d 6f 64 20 37 37 37 20 2a 3b 20 73 68 20 [0-10] 3b 20 74 66 74 70 20 2d 67 20 [0-15] 20 2d 72 20 74 66 74 70 2e 73 68 3b 20 63 68 6d 6f 64 20 37 37 37 20 2a 3b 20 73 68 20 74 66 74 70 2e 73 68 3b 20 72 6d 20 2d 72 66 20 2a 2e 73 68 } //1
		$a_00_1 = {77 77 77 2e 62 69 6c 6c 79 62 6f 62 62 6f 74 2e 63 6f 6d 2f 63 72 61 77 6c 65 72 } //1 www.billybobbot.com/crawler
		$a_00_2 = {39 36 6d 42 4f 54 20 4a 4f 49 4e 45 44 } //1 96mBOT JOINED
		$a_00_3 = {6e 70 78 58 6f 75 64 69 66 46 65 45 67 47 61 41 43 53 63 73 } //1 npxXoudifFeEgGaACScs
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}