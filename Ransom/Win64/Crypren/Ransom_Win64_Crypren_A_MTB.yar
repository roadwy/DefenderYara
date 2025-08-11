
rule Ransom_Win64_Crypren_A_MTB{
	meta:
		description = "Ransom:Win64/Crypren.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {2e 6c 6f 63 6b 65 64 } //1 .locked
		$a_81_1 = {44 65 63 72 79 70 74 20 46 69 6c 65 73 } //1 Decrypt Files
		$a_81_2 = {44 65 63 72 79 70 74 69 6f 6e 20 77 6f 75 6c 64 20 72 75 6e 20 68 65 72 65 2e } //1 Decryption would run here.
		$a_81_3 = {49 6e 63 6f 72 72 65 63 74 20 70 61 73 73 77 6f 72 64 2e } //1 Incorrect password.
		$a_81_4 = {52 61 6e 73 6f 6d 53 69 6d 57 6e 64 } //1 RansomSimWnd
		$a_81_5 = {59 6f 75 72 20 66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 } //1 Your files have been encrypted
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}