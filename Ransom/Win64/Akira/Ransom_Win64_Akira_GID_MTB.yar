
rule Ransom_Win64_Akira_GID_MTB{
	meta:
		description = "Ransom:Win64/Akira.GID!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {72 65 61 64 6d 65 2d 61 73 6c 64 6b 61 73 2e 74 78 74 } //1 readme-asldkas.txt
		$a_01_1 = {63 68 65 63 6b 2d 68 65 72 65 2e 74 78 74 } //1 check-here.txt
		$a_01_2 = {61 6c 6c 20 79 6f 75 72 20 62 61 63 6b 75 70 73 20 2d 20 76 69 72 74 75 61 6c 2c 20 70 68 79 73 69 63 61 6c 20 2d 20 65 76 65 72 79 74 68 69 6e 67 20 74 68 61 74 20 77 65 20 6d 61 6e 61 67 65 64 20 74 6f 20 72 65 61 63 68 20 2d 20 61 72 65 20 63 6f 6d 70 6c 65 74 65 6c 79 20 72 65 6d 6f 76 65 64 2e 20 4d 6f 72 65 6f 76 65 72 2c 20 77 65 20 68 61 76 65 20 74 61 6b 65 6e 20 61 20 67 72 65 61 74 20 61 6d 6f 75 6e 74 20 6f 66 20 79 6f 75 72 20 63 6f 72 70 6f 72 61 74 65 20 64 61 74 61 20 70 72 69 6f 72 20 74 6f 20 65 6e 63 72 79 70 74 69 6f 6e } //1 all your backups - virtual, physical - everything that we managed to reach - are completely removed. Moreover, we have taken a great amount of your corporate data prior to encryption
		$a_01_3 = {57 68 61 74 65 76 65 72 20 77 68 6f 20 79 6f 75 20 61 72 65 20 61 6e 64 20 77 68 61 74 20 79 6f 75 72 20 74 69 74 6c 65 20 69 73 20 69 66 20 79 6f 75 27 72 65 20 72 65 61 64 69 6e 67 20 74 68 69 73 20 69 74 20 6d 65 61 6e 73 20 74 68 65 20 69 6e 74 65 72 6e 61 6c 20 69 6e 66 72 61 73 74 72 75 63 74 75 72 65 20 6f 66 20 79 6f 75 72 20 63 6f 6d 70 61 6e 79 20 69 73 20 66 75 6c 6c 79 20 6f 72 20 70 61 72 74 69 61 6c 6c 79 20 64 65 61 64 } //1 Whatever who you are and what your title is if you're reading this it means the internal infrastructure of your company is fully or partially dead
		$a_01_4 = {57 65 6c 6c 2c 20 66 6f 72 20 6e 6f 77 20 6c 65 74 27 73 20 6b 65 65 70 20 61 6c 6c 20 74 68 65 20 74 65 61 72 73 20 61 6e 64 20 72 65 73 65 6e 74 6d 65 6e 74 20 74 6f 20 6f 75 72 73 65 6c 76 65 73 20 61 6e 64 20 74 72 79 20 74 6f 20 62 75 69 6c 64 20 61 20 63 6f 6e 73 74 72 75 63 74 69 76 65 20 64 69 61 6c 6f 67 75 65 } //1 Well, for now let's keep all the tears and resentment to ourselves and try to build a constructive dialogue
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}