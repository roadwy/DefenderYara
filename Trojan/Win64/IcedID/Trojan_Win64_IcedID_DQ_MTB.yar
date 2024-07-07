
rule Trojan_Win64_IcedID_DQ_MTB{
	meta:
		description = "Trojan:Win64/IcedID.DQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {54 78 50 38 32 77 76 79 4c } //1 TxP82wvyL
		$a_01_1 = {47 46 4f 48 36 6b 63 57 77 64 63 } //1 GFOH6kcWwdc
		$a_01_2 = {4d 53 73 6b 44 39 63 } //1 MSskD9c
		$a_01_3 = {50 55 30 43 30 4d 41 55 } //1 PU0C0MAU
		$a_01_4 = {52 31 41 6a 68 79 51 43 76 56 } //1 R1AjhyQCvV
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}