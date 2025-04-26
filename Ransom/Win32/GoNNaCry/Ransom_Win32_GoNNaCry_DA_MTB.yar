
rule Ransom_Win32_GoNNaCry_DA_MTB{
	meta:
		description = "Ransom:Win32/GoNNaCry.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_81_0 = {47 6f 20 62 75 69 6c 64 20 49 44 3a } //2 Go build ID:
		$a_81_1 = {4f 6f 70 73 2c 20 41 6c 6c 20 79 6f 75 72 20 69 6d 70 6f 72 74 61 6e 74 20 66 69 6c 65 73 20 61 72 65 20 65 6e 63 72 79 70 74 65 64 20 21 } //1 Oops, All your important files are encrypted !
		$a_81_2 = {41 6c 6c 20 79 6f 75 72 20 66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 20 77 69 74 68 20 73 74 72 6f 6e 67 20 65 6e 63 72 79 70 74 69 6f 6e 20 61 6c 67 6f 72 69 74 68 6d } //1 All your files have been encrypted with strong encryption algorithm
		$a_81_3 = {47 6f 4e 4e 61 43 72 79 } //1 GoNNaCry
	condition:
		((#a_81_0  & 1)*2+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=3
 
}