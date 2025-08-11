
rule Ransom_MSIL_FileCoder_BAD_MTB{
	meta:
		description = "Ransom:MSIL/FileCoder.BAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {2f 4c 49 53 54 20 4f 46 20 45 4e 43 52 59 50 54 45 44 20 46 49 4c 45 53 } //1 /LIST OF ENCRYPTED FILES
		$a_81_1 = {20 46 49 4c 45 53 20 57 45 52 45 20 45 4e 43 52 59 50 54 45 44 20 53 55 43 43 45 53 53 46 55 4c 4c 59 } //1  FILES WERE ENCRYPTED SUCCESSFULLY
		$a_81_2 = {2f 50 41 59 4d 45 4e 54 20 49 4e 53 54 52 55 43 54 49 4f 4e 53 } //1 /PAYMENT INSTRUCTIONS
		$a_81_3 = {20 68 6f 75 72 73 20 77 69 6c 6c 20 72 65 73 75 6c 74 20 69 6e 20 74 68 65 20 72 61 6e 73 6f 6d 20 61 6d 6f 75 6e 74 20 69 6e 63 72 65 61 73 69 6e 67 20 74 6f } //1  hours will result in the ransom amount increasing to
		$a_81_4 = {2f 48 4f 57 20 54 4f 20 44 45 43 52 59 50 54 } //1 /HOW TO DECRYPT
		$a_81_5 = {2f 41 6c 6c 4c 6f 63 6b 65 64 2e 74 78 74 } //1 /AllLocked.txt
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}