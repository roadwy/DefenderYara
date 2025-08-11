
rule Ransom_Win64_Filecoder_CCJX_MTB{
	meta:
		description = "Ransom:Win64/Filecoder.CCJX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 "
		
	strings :
		$a_01_0 = {49 4e 43 2d 52 45 41 44 4d 45 2e 74 78 74 2e 2e 77 69 6e 64 6f 77 73 70 72 6f 67 72 61 6d 20 66 69 6c 65 73 61 70 70 64 61 74 61 24 72 65 63 79 63 6c 65 2e 62 69 6e 49 4e 43 2e 6c 6f 67 2e 64 6c 6c } //2 INC-README.txt..windowsprogram filesappdata$recycle.binINC.log.dll
		$a_01_1 = {53 75 63 63 65 73 73 66 75 6c 6c 79 20 64 65 6c 65 74 65 64 20 73 68 61 64 6f 77 20 63 6f 70 69 65 73 20 66 72 6f 6d } //1 Successfully deleted shadow copies from
		$a_01_2 = {53 75 63 63 65 73 73 66 75 6c 6c 79 20 6b 69 6c 6c 65 64 20 70 72 6f 63 65 73 73 65 73 20 62 79 20 6d 61 73 6b } //1 Successfully killed processes by mask
		$a_01_3 = {53 75 63 63 65 73 73 66 75 6c 6c 79 20 6b 69 6c 6c 65 64 20 73 65 72 76 69 63 65 73 20 62 79 20 6d 61 73 6b } //1 Successfully killed services by mask
		$a_01_4 = {77 68 69 6c 65 20 65 6e 63 72 79 70 74 69 6e 67 20 66 69 6c 65 3a } //1 while encrypting file:
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=6
 
}