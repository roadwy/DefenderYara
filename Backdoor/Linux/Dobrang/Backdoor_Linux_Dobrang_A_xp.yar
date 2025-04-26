
rule Backdoor_Linux_Dobrang_A_xp{
	meta:
		description = "Backdoor:Linux/Dobrang.A!xp,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {72 61 6e 7a 6f 75 3a 20 69 6e 76 61 6c 69 64 20 70 6f 72 74 20 6e 75 6d 62 65 72 2e } //1 ranzou: invalid port number.
		$a_01_1 = {72 61 6e 7a 6f 75 20 2d 2d 68 65 6c 70 } //1 ranzou --help
		$a_01_2 = {2f 62 69 6e 2f 73 68 20 2d 69 } //1 /bin/sh -i
		$a_01_3 = {47 6f 69 6e 67 20 69 6e 20 74 68 65 20 62 61 63 6b 67 72 6f 75 6e 64 } //1 Going in the background
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}