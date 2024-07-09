
rule Backdoor_Linux_Tsunami_A_MTB{
	meta:
		description = "Backdoor:Linux/Tsunami.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 06 00 00 "
		
	strings :
		$a_01_0 = {58 54 43 20 42 4f 54 4e 45 54 } //1 XTC BOTNET
		$a_00_1 = {6b 61 69 74 65 6e 20 62 6f 74 20 70 72 6f 63 63 65 73 73 65 73 } //1 kaiten bot proccesses
		$a_00_2 = {68 65 6c 6c 72 6f 6f 6d } //1 hellroom
		$a_02_3 = {77 67 65 74 24 7b 49 46 53 7d 68 74 74 70 3a 2f 2f [0-12] 2f 61 72 6d 37 } //1
		$a_00_4 = {6b 65 79 50 61 74 68 3d 25 32 37 25 30 41 2f 62 69 6e 2f 73 68 } //1 keyPath=%27%0A/bin/sh
		$a_00_5 = {53 65 6c 66 20 52 65 70 20 46 75 63 6b 69 6e 67 20 4e 65 54 69 53 20 61 6e 64 20 54 68 69 73 69 74 79 } //1 Self Rep Fucking NeTiS and Thisity
	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_02_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=4
 
}