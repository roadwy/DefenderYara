
rule Ransom_Win64_RAWorld_YAF_MTB{
	meta:
		description = "Ransom:Win64/RAWorld.YAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 07 00 00 "
		
	strings :
		$a_01_0 = {52 41 20 57 6f 72 6c 64 } //1 RA World
		$a_01_1 = {64 61 74 61 20 61 72 65 20 73 74 6f 6c 65 6e 20 61 6e 64 20 65 6e 63 72 79 70 74 65 64 } //1 data are stolen and encrypted
		$a_01_2 = {64 6f 6e 27 74 20 70 61 79 } //1 don't pay
		$a_01_3 = {72 65 6c 65 61 73 65 20 74 68 65 20 64 61 74 61 } //1 release the data
		$a_01_4 = {64 65 63 72 79 70 74 20 73 6f 6d 65 20 66 69 6c 65 73 } //1 decrypt some files
		$a_01_5 = {64 65 63 72 79 70 74 69 6f 6e 20 74 6f 6f 6c 20 } //1 decryption tool 
		$a_01_6 = {74 68 65 20 68 69 67 68 65 72 20 72 61 6e 73 6f 6d } //1 the higher ransom
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=5
 
}