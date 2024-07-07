
rule Ransom_Linux_DarkSide_A_MTB{
	meta:
		description = "Ransom:Linux/DarkSide.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 05 00 00 "
		
	strings :
		$a_00_0 = {57 65 6c 63 6f 6d 65 20 74 6f 20 44 61 72 6b 53 69 64 65 } //1 Welcome to DarkSide
		$a_00_1 = {59 6f 75 72 20 63 6f 6d 70 75 74 65 72 73 20 61 6e 64 20 73 65 72 76 65 72 73 20 61 72 65 20 65 6e 63 72 79 70 74 65 64 2c 20 62 61 63 6b 75 70 73 20 61 72 65 20 64 65 6c 65 74 65 64 } //1 Your computers and servers are encrypted, backups are deleted
		$a_00_2 = {64 61 72 6b 73 69 64 65 5f 72 65 61 64 6d 65 2e 74 78 74 } //1 darkside_readme.txt
		$a_02_3 = {50 61 72 74 69 61 6c 20 46 69 6c 65 20 45 6e 63 72 79 70 74 69 6f 6e 20 54 6f 6f 6c 90 02 20 50 61 72 74 69 61 6c 46 69 6c 65 43 72 79 70 74 65 72 20 5b 2d 68 5d 20 5b 2d 66 3a 66 69 6c 65 5d 20 5b 2d 73 3a 73 69 7a 65 5d 20 5b 2d 6b 3a 6b 65 79 5d 90 02 25 50 61 72 74 69 61 6c 46 69 6c 65 43 72 79 70 74 65 72 20 20 2d 66 20 69 6e 70 75 74 2e 66 69 6c 65 90 00 } //1
		$a_00_4 = {2f 74 6d 70 2f 73 6f 66 74 77 61 72 65 2e 6c 6f 67 } //1 /tmp/software.log
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_02_3  & 1)*1+(#a_00_4  & 1)*1) >=3
 
}