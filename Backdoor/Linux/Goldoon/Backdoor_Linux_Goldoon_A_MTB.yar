
rule Backdoor_Linux_Goldoon_A_MTB{
	meta:
		description = "Backdoor:Linux/Goldoon.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_03_0 = {31 38 35 2e 31 30 36 2e 39 34 2e 35 31 00 [0-10] 6c 69 6e 75 78 } //1
		$a_03_1 = {63 68 6d 6f 64 00 65 78 65 63 76 70 00 [0-10] 5f } //1
		$a_00_2 = {55 73 65 72 2d 41 67 65 6e 74 3a 20 46 42 49 2d 41 67 65 6e 74 20 28 43 68 65 63 6b 69 6e 67 20 59 6f 75 29 } //1 User-Agent: FBI-Agent (Checking You)
		$a_00_3 = {59 65 73 49 74 73 41 6e 41 6e 74 69 48 6f 6e 65 79 70 6f 74 42 61 62 79 } //1 YesItsAnAntiHoneypotBaby
		$a_00_4 = {79 65 73 49 74 73 53 75 73 79 62 61 62 79 } //1 yesItsSusybaby
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=4
 
}