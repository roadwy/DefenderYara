
rule Ransom_Win64_Filecoder_SB_MTB{
	meta:
		description = "Ransom:Win64/Filecoder.SB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_02_0 = {59 00 6f 00 75 00 72 00 20 00 46 00 69 00 6c 00 65 00 73 00 [0-20] 45 00 6e 00 63 00 72 00 79 00 70 00 74 00 65 00 64 00 } //1
		$a_02_1 = {59 6f 75 72 20 46 69 6c 65 73 [0-20] 45 6e 63 72 79 70 74 65 64 } //1
		$a_80_2 = {69 2e 69 6d 67 75 72 2e 63 6f 6d } //i.imgur.com  1
		$a_80_3 = {74 61 6e 74 6f 70 6f 72 63 69 65 6e 74 6f 2e 63 6f 6d } //tantoporciento.com  1
		$a_80_4 = {46 4f 52 20 44 45 43 52 59 50 54 20 59 4f 55 52 20 46 49 4c 45 53 } //FOR DECRYPT YOUR FILES  1
		$a_80_5 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 57 } //URLDownloadToFileW  1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1) >=5
 
}