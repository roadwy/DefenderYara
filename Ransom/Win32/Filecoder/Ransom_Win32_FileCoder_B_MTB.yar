
rule Ransom_Win32_FileCoder_B_MTB{
	meta:
		description = "Ransom:Win32/FileCoder.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 0a 00 00 "
		
	strings :
		$a_81_0 = {59 6f 75 72 20 70 65 72 73 6f 6e 61 6c 20 66 69 6c 65 73 20 61 72 65 20 62 65 69 6e 67 20 64 65 6c 65 74 65 64 2e 20 59 6f 75 72 20 70 68 6f 74 6f 73 2c 20 76 69 64 65 6f 73 2c 20 64 6f 63 75 6d 65 6e 74 73 2c 20 65 74 63 } //1 Your personal files are being deleted. Your photos, videos, documents, etc
		$a_81_1 = {49 20 77 61 6e 74 20 74 6f 20 70 6c 61 79 20 61 20 67 61 6d 65 20 77 69 74 68 20 79 6f 75 2e 2e 2c 20 68 6f 77 65 76 65 72 2c 20 6c 65 74 20 6d 65 20 65 78 70 6c 61 69 6e 20 74 68 65 20 67 6f 6c 64 65 6e 20 52 55 4c 45 53 } //1 I want to play a game with you.., however, let me explain the golden RULES
		$a_81_2 = {42 75 74 2c 20 64 6f 6e 27 74 20 77 6f 72 72 79 21 20 49 74 20 77 69 6c 6c 20 6f 6e 6c 79 20 68 61 70 70 65 6e 20 69 66 20 79 6f 75 20 64 6f 6e 27 74 20 63 6f 6d 70 6c 79 } //1 But, don't worry! It will only happen if you don't comply
		$a_81_3 = {48 6f 77 65 76 65 72 2c 20 49 27 76 65 20 61 6c 72 65 61 64 79 20 65 6e 63 72 79 70 74 65 64 20 79 6f 75 72 20 70 65 72 73 6f 6e 61 6c 20 66 69 6c 65 73 2c 20 73 6f 20 79 6f 75 20 63 61 6e 6e 6f 74 20 61 63 63 65 73 73 20 74 68 65 6d 2e } //1 However, I've already encrypted your personal files, so you cannot access them.
		$a_81_4 = {42 79 20 74 68 65 20 77 61 79 2c 20 49 20 68 6f 70 65 20 79 6f 75 20 64 6f 6e 27 74 20 6b 65 65 70 20 6e 75 64 65 73 27 20 70 68 6f 74 6f 73 20 61 6e 64 20 76 69 64 65 6f 73 20 6f 72 20 69 6c 6c 65 67 61 6c 20 62 75 73 69 6e 65 73 73 } //1 By the way, I hope you don't keep nudes' photos and videos or illegal business
		$a_81_5 = {73 68 6f 75 6c 64 20 79 6f 75 20 72 65 73 74 61 72 74 20 74 68 65 20 63 6f 6d 70 75 74 65 72 2c 20 47 61 6d 65 20 4f 76 65 72 21 21 21 2c 20 79 6f 75 20 6c 6f 73 65 } //1 should you restart the computer, Game Over!!!, you lose
		$a_81_6 = {57 61 73 74 69 6e 67 20 79 6f 75 72 20 6b 65 79 20 65 6e 74 72 69 65 73 20 77 69 6c 6c 20 6a 75 73 74 20 63 61 75 73 65 20 70 65 72 6d 61 6e 65 6e 74 20 64 61 74 61 20 64 61 6d 61 67 65 20 74 6f 20 79 6f 75 72 20 63 6f 6d 70 75 74 65 72 } //1 Wasting your key entries will just cause permanent data damage to your computer
		$a_81_7 = {47 72 65 61 74 20 6a 6f 62 2c 20 49 27 6d 20 64 65 63 72 79 70 74 69 6e 67 20 79 6f 75 72 20 66 69 6c 65 73 } //1 Great job, I'm decrypting your files
		$a_81_8 = {45 6e 63 72 79 70 74 65 64 5f 46 69 6c 65 4c 69 73 74 2e 74 78 74 } //1 Encrypted_FileList.txt
		$a_81_9 = {5c 52 65 6c 65 61 73 65 5c 43 6f 63 6f 32 30 32 30 2e 70 64 62 } //1 \Release\Coco2020.pdb
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1) >=6
 
}