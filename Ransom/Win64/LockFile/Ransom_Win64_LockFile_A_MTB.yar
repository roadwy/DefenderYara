
rule Ransom_Win64_LockFile_A_MTB{
	meta:
		description = "Ransom:Win64/LockFile.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {65 6e 63 72 79 70 74 64 65 63 72 79 70 74 } //1 encryptdecrypt
		$a_81_1 = {2e 72 75 73 74 73 6f 6d 77 61 72 65 } //1 .rustsomware
		$a_00_2 = {20 70 61 79 20 } //1  pay 
		$a_00_3 = {2f 72 75 73 74 63 2f } //1 /rustc/
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}