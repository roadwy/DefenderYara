
rule Ransom_MSIL_Filecoder_EO_MTB{
	meta:
		description = "Ransom:MSIL/Filecoder.EO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {30 52 78 77 45 51 77 67 74 6b 53 57 43 39 73 4e 54 54 2e 65 78 50 63 4b 72 62 53 62 31 32 4d 37 35 6d 66 63 73 } //1 0RxwEQwgtkSWC9sNTT.exPcKrbSb12M75mfcs
		$a_81_1 = {4d 76 66 64 66 76 4b 4e 55 64 77 76 78 66 70 4d 34 50 2e 32 76 70 6c 35 75 53 39 4c 30 51 33 63 58 5a 67 6f 4f } //1 MvfdfvKNUdwvxfpM4P.2vpl5uS9L0Q3cXZgoO
		$a_81_2 = {47 6f 72 67 6f 6e 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //1 Gorgon.Properties.Resources
		$a_81_3 = {7b 31 31 31 31 31 2d 32 32 32 32 32 2d 32 30 30 30 31 2d 30 30 30 30 30 7d } //1 {11111-22222-20001-00000}
		$a_81_4 = {7b 31 31 31 31 31 2d 32 32 32 32 32 2d 31 30 30 30 39 2d 31 31 31 31 32 7d } //1 {11111-22222-10009-11112}
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}