
rule Ransom_Win64_Basta_AN_MTB{
	meta:
		description = "Ransom:Win64/Basta.AN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {57 65 6c 63 6f 6d 65 20 74 6f 20 42 75 6c 6c 73 20 61 6e 64 20 43 6f 77 73 2c 20 61 20 66 75 6e 20 77 6f 72 64 20 67 61 6d 65 } //1 Welcome to Bulls and Cows, a fun word game
		$a_01_1 = {49 27 6d 20 74 68 69 6e 6b 69 6e 67 20 6f 66 } //1 I'm thinking of
		$a_01_2 = {44 6f 20 79 6f 75 20 77 61 6e 74 20 74 6f 20 70 6c 61 79 20 61 67 61 69 6e 20 77 69 74 68 20 74 68 65 20 73 61 6d 65 20 68 69 64 64 65 6e 20 77 6f 72 64 20 28 79 2f 6e 29 } //1 Do you want to play again with the same hidden word (y/n)
		$a_01_3 = {57 45 4c 4c 20 44 4f 4e 45 20 2d 20 59 4f 55 20 57 49 4e 21 } //1 WELL DONE - YOU WIN!
		$a_01_4 = {52 65 6c 65 61 73 65 5c 42 75 6c 6c 43 6f 77 47 61 6d 65 2e 70 64 62 } //1 Release\BullCowGame.pdb
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}