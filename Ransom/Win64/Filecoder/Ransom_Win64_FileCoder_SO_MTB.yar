
rule Ransom_Win64_FileCoder_SO_MTB{
	meta:
		description = "Ransom:Win64/FileCoder.SO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 05 00 00 "
		
	strings :
		$a_81_0 = {25 73 2e 73 6d 65 72 74 } //2 %s.smert
		$a_81_1 = {25 73 5c 52 45 41 44 4d 45 2e 74 78 74 } //2 %s\README.txt
		$a_81_2 = {59 6f 75 72 20 66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 66 75 63 6b 65 64 2e 20 54 68 65 72 65 27 73 20 6e 6f 20 77 61 79 20 62 61 63 6b } //2 Your files have been fucked. There's no way back
		$a_81_3 = {57 68 61 74 20 63 61 6e 20 79 6f 75 20 64 6f 20 61 62 6f 75 74 20 69 74 } //2 What can you do about it
		$a_81_4 = {53 74 61 72 74 20 61 6c 6c 20 6f 76 65 72 20 61 67 61 69 6e } //2 Start all over again
	condition:
		((#a_81_0  & 1)*2+(#a_81_1  & 1)*2+(#a_81_2  & 1)*2+(#a_81_3  & 1)*2+(#a_81_4  & 1)*2) >=10
 
}