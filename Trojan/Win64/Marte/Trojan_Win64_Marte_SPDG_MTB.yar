
rule Trojan_Win64_Marte_SPDG_MTB{
	meta:
		description = "Trojan:Win64/Marte.SPDG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_81_0 = {46 34 61 73 2f 6b 4d 69 68 37 4b 56 4c 69 69 34 35 6d 50 73 49 6a 57 6c 37 2f 31 38 75 58 4c 38 } //2 F4as/kMih7KVLii45mPsIjWl7/18uXL8
		$a_81_1 = {64 5a 65 49 4c 74 6c 67 43 } //1 dZeILtlgC
		$a_81_2 = {73 4f 72 65 6c 6f 63 34 } //1 sOreloc4
		$a_81_3 = {54 4e 4e 68 78 79 6e } //1 TNNhxyn
	condition:
		((#a_81_0  & 1)*2+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=5
 
}