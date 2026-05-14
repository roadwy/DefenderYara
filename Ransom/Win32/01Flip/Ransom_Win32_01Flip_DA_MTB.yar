
rule Ransom_Win32_01Flip_DA_MTB{
	meta:
		description = "Ransom:Win32/01Flip.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,11 00 11 00 04 00 00 "
		
	strings :
		$a_81_0 = {59 6f 75 72 20 66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 2e } //10 Your files have been encrypted.
		$a_81_1 = {30 31 46 6c 69 70 40 70 72 6f 74 6f 6e 2e 6d 65 } //5 01Flip@proton.me
		$a_81_2 = {73 65 6e 64 20 61 20 66 72 69 65 6e 64 20 72 65 71 75 65 73 74 } //1 send a friend request
		$a_81_3 = {64 65 63 72 79 70 74 69 6f 6e 20 6b 65 79 } //1 decryption key
	condition:
		((#a_81_0  & 1)*10+(#a_81_1  & 1)*5+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=17
 
}