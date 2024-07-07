
rule Ransom_Win64_BianLian_PA_MTB{
	meta:
		description = "Ransom:Win64/BianLian.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_00_0 = {6d 61 69 6e 2e 65 6e 63 72 79 70 74 00 } //1
		$a_00_1 = {47 6f 20 62 75 69 6c 64 20 49 44 3a } //1 Go build ID:
		$a_00_2 = {63 72 79 70 74 6f 2f 63 69 70 68 65 72 2e 78 6f 72 42 79 74 65 73 53 53 45 32 } //1 crypto/cipher.xorBytesSSE2
		$a_01_3 = {4c 6f 6f 6b 20 61 74 20 74 68 69 73 20 69 6e 73 74 72 75 63 74 69 6f 6e 2e 74 78 74 } //1 Look at this instruction.txt
		$a_01_4 = {62 69 61 6e 6c 69 61 6e 32 34 34 31 34 30 36 32 35 } //1 bianlian244140625
		$a_01_5 = {74 65 78 74 3d 20 20 7a 6f 6d 62 69 65 } //1 text=  zombie
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}