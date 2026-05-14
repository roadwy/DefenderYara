
rule Ransom_Win64_AiLock_PGAG_MTB{
	meta:
		description = "Ransom:Win64/AiLock.PGAG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_81_0 = {2e 41 69 4c 6f 63 6b } //1 .AiLock
		$a_80_1 = {52 65 61 64 4d 65 2e 74 78 74 } //ReadMe.txt  1
		$a_80_2 = {2e 41 69 52 65 63 6f 76 65 72 79 } //.AiRecovery  1
		$a_80_3 = {72 65 61 64 3d 25 75 20 4d 62 2f 73 2c 20 77 72 69 74 65 3d 25 75 20 4d 62 2f 73 2c 20 6f 70 65 6e 65 64 3d 25 75 2c 20 65 6e 63 50 53 3d 25 75 2c 20 74 6f 74 61 6c 46 6f 75 6e 64 3d 25 75 2c 20 54 6f 74 61 6c 45 6e 63 72 79 70 74 65 64 3d 25 75 } //read=%u Mb/s, write=%u Mb/s, opened=%u, encPS=%u, totalFound=%u, TotalEncrypted=%u  1
		$a_80_4 = {2e 41 69 4c 6f 63 6b 5c 44 65 66 61 75 6c 74 49 63 6f 6e } //.AiLock\DefaultIcon  1
		$a_01_5 = {53 68 65 6c 6c 45 78 65 63 75 74 65 57 } //1 ShellExecuteW
		$a_80_6 = {53 74 61 72 74 20 4c 6f 67 3a 25 64 20 4e 65 74 77 6f 72 6b 3a 25 64 20 53 65 6c 66 64 65 6c 65 74 65 3a 25 64 20 50 61 74 68 3d 25 73 } //Start Log:%d Network:%d Selfdelete:%d Path=%s  1
		$a_80_7 = {54 6f 74 61 6c 20 74 69 6d 65 20 6f 66 20 65 6e 63 72 79 70 74 69 6f 6e 3a } //Total time of encryption:  1
	condition:
		((#a_81_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_01_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1) >=8
 
}