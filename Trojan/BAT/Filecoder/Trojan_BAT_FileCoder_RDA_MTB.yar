
rule Trojan_BAT_FileCoder_RDA_MTB{
	meta:
		description = "Trojan:BAT/FileCoder.RDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {50 61 79 55 70 4f 52 43 72 79 } //1 PayUpORCry
		$a_01_1 = {32 62 63 38 31 31 37 38 2d 30 34 65 31 2d 34 61 32 65 2d 62 39 38 32 2d 64 62 65 37 65 33 33 35 37 38 30 31 } //1 2bc81178-04e1-4a2e-b982-dbe7e3357801
		$a_01_2 = {75 73 65 72 33 32 } //1 user32
		$a_01_3 = {53 79 73 74 65 6d 50 61 72 61 6d 65 74 65 72 73 49 6e 66 6f } //1 SystemParametersInfo
		$a_01_4 = {30 34 30 30 66 30 33 65 2d 38 34 62 65 2d 34 64 66 39 2d 62 39 33 31 2d 65 39 32 38 32 61 62 32 62 35 62 63 } //1 0400f03e-84be-4df9-b931-e9282ab2b5bc
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}