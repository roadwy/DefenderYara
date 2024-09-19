
rule Ransom_Win64_blackcat_DA_MTB{
	meta:
		description = "Ransom:Win64/blackcat.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,19 00 19 00 07 00 00 "
		
	strings :
		$a_81_0 = {66 69 6c 65 73 20 6f 6e 20 79 6f 75 72 20 73 79 73 74 65 6d 20 77 61 73 20 45 4e 43 52 59 50 54 45 44 } //20 files on your system was ENCRYPTED
		$a_81_1 = {62 6c 61 63 6b 63 61 74 } //1 blackcat
		$a_03_2 = {52 00 45 00 43 00 4f 00 56 00 45 00 52 00 2d 00 [0-0f] 2d 00 46 00 49 00 4c 00 45 00 53 00 2e 00 74 00 78 00 74 00 } //1
		$a_03_3 = {52 45 43 4f 56 45 52 2d [0-0f] 2d 46 49 4c 45 53 2e 74 78 74 } //1
		$a_81_4 = {76 73 73 61 64 6d 69 6e 2e 65 78 65 20 44 65 6c 65 74 65 20 53 68 61 64 6f 77 73 20 2f 61 6c 6c 20 2f 71 75 69 65 74 } //1 vssadmin.exe Delete Shadows /all /quiet
		$a_81_5 = {74 6f 72 70 72 6f 6a 65 63 74 2e 6f 72 67 } //1 torproject.org
		$a_81_6 = {4b 69 6c 6c 69 6e 67 20 70 72 6f 63 65 73 73 65 73 } //1 Killing processes
	condition:
		((#a_81_0  & 1)*20+(#a_81_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=25
 
}