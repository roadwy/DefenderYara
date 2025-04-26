
rule Backdoor_Linux_Gafgyt_A_MTB{
	meta:
		description = "Backdoor:Linux/Gafgyt.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 07 00 00 "
		
	strings :
		$a_00_0 = {2f 78 35 34 2f 78 35 33 2f 78 36 66 2f 78 37 35 2f 78 37 32 2f 78 36 33 2f 78 36 35 2f 78 32 30 2f 78 34 35 2f 78 36 65 2f 78 36 37 2f 78 36 39 2f 78 36 65 2f 78 36 35 2f 78 32 30 2f 78 35 31 2f 78 37 35 2f 78 36 35 2f 78 37 32 2f 78 37 39 } //1 /x54/x53/x6f/x75/x72/x63/x65/x20/x45/x6e/x67/x69/x6e/x65/x20/x51/x75/x65/x72/x79
		$a_00_1 = {4b 49 4c 4c 41 4c 4c } //1 KILLALL
		$a_00_2 = {62 6f 74 6e 61 6d 65 3a } //1 botname:
		$a_00_3 = {64 61 79 7a 64 64 6f 73 2e 63 6f } //2 dayzddos.co
		$a_00_4 = {76 73 65 61 74 74 61 63 6b } //1 vseattack
		$a_00_5 = {73 74 64 68 65 78 66 6c 6f 6f 64 } //1 stdhexflood
		$a_00_6 = {6c 6f 6c 6f 6c 6f 6c 6f 6c 6f 6c } //1 lololololol
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*2+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=4
 
}