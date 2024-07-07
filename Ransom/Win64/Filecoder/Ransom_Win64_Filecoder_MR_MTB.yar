
rule Ransom_Win64_Filecoder_MR_MTB{
	meta:
		description = "Ransom:Win64/Filecoder.MR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 06 00 00 "
		
	strings :
		$a_81_0 = {5c 45 4e 43 52 49 50 54 41 52 5c 78 36 34 5c 52 65 6c 65 61 73 65 5c 45 4e 43 52 49 50 54 41 52 2e 70 64 62 } //5 \ENCRIPTAR\x64\Release\ENCRIPTAR.pdb
		$a_81_1 = {42 69 74 63 6f 69 6e 20 77 61 6c 6c 65 74 3a 20 33 51 74 62 41 69 6f 42 53 77 32 34 39 4a 35 78 73 47 64 31 73 43 71 54 71 68 64 44 58 34 43 44 39 4c } //5 Bitcoin wallet: 3QtbAioBSw249J5xsGd1sCqTqhdDX4CD9L
		$a_81_2 = {63 61 6e 74 20 6f 70 65 6e 20 79 6f 75 72 20 66 69 6c 65 73 } //5 cant open your files
		$a_81_3 = {5c 5f 5f 52 45 41 44 5f 4d 45 5f } //5 \__READ_ME_
		$a_81_4 = {73 61 6d 6d 79 37 30 70 5f 79 36 31 6d 40 62 75 78 6f 64 2e 63 6f 6d } //1 sammy70p_y61m@buxod.com
		$a_81_5 = {57 68 65 6e 20 77 65 20 76 65 72 69 66 79 20 74 68 65 20 74 72 61 6e 73 66 65 72 20 77 65 20 77 69 6c 6c 20 73 65 6e 64 20 79 6f 75 20 74 68 65 20 74 6f 6f 6c } //1 When we verify the transfer we will send you the tool
	condition:
		((#a_81_0  & 1)*5+(#a_81_1  & 1)*5+(#a_81_2  & 1)*5+(#a_81_3  & 1)*5+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=21
 
}