
rule Ransom_Win64_Snatch_PC_MTB{
	meta:
		description = "Ransom:Win64/Snatch.PC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 04 00 00 "
		
	strings :
		$a_01_0 = {2e 65 6e 63 32 30 32 34 30 37 } //1 .enc202407
		$a_01_1 = {52 65 61 64 4d 65 2e 74 78 74 } //1 ReadMe.txt
		$a_01_2 = {6d 61 69 6e 2e 65 6e 63 72 79 70 74 46 69 6c 65 } //1 main.encryptFile
		$a_01_3 = {41 6c 6c 20 79 6f 75 72 20 64 61 74 61 20 68 61 73 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 20 62 79 20 6d 65 } //4 All your data has been encrypted by me
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*4) >=7
 
}