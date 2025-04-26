
rule Ransom_Win32_LockBit_PE_MTB{
	meta:
		description = "Ransom:Win32/LockBit.PE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {50 00 6f 00 30 00 71 00 37 00 4f 00 50 00 73 00 37 00 49 00 } //1 Po0q7OPs7I
		$a_01_1 = {52 00 65 00 73 00 74 00 6f 00 72 00 65 00 2d 00 4d 00 79 00 2d 00 46 00 69 00 6c 00 65 00 73 00 2e 00 74 00 78 00 74 00 } //1 Restore-My-Files.txt
		$a_01_2 = {41 6c 6c 20 79 6f 75 72 20 69 6d 70 6f 72 74 61 6e 74 20 66 69 6c 65 73 20 61 72 65 20 65 6e 63 72 79 70 74 65 64 21 } //1 All your important files are encrypted!
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}