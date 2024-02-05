
rule Ransom_Win64_FileCrypter_MA_MTB{
	meta:
		description = "Ransom:Win64/FileCrypter.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_81_0 = {47 6f 20 62 75 69 6c 64 20 49 44 3a } //01 00 
		$a_81_1 = {61 73 20 20 61 74 20 20 66 70 3d 20 69 73 20 20 6c 72 3a 20 6f 66 20 20 6f 6e 20 20 70 63 3d 20 73 70 3a 20 73 70 3d 25 78 } //01 00 
		$a_81_2 = {49 6e 66 2e 62 61 74 2e 63 6d 64 2e 63 6f 6d 2e 63 73 73 2e 65 78 65 2e 67 69 66 2e 68 74 6d 2e 6a 70 67 2e 6d 6a 73 2e 70 64 66 2e 70 6e 67 2e 73 76 67 2e 78 6d 6c } //01 00 
		$a_81_3 = {6d 61 69 6e 2e 72 61 6e 73 6f 6d 4e 6f 74 65 } //01 00 
		$a_81_4 = {2e 65 6e 63 72 79 70 74 65 64 } //01 00 
		$a_81_5 = {75 6e 72 65 61 63 68 61 62 6c 65 75 73 65 72 65 6e 76 2e 64 6c 6c } //00 00 
	condition:
		any of ($a_*)
 
}