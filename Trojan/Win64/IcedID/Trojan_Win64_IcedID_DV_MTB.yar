
rule Trojan_Win64_IcedID_DV_MTB{
	meta:
		description = "Trojan:Win64/IcedID.DV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 05 00 00 "
		
	strings :
		$a_01_0 = {47 75 61 79 62 73 64 6e 6a 75 62 78 79 61 68 6a 73 61 } //10 Guaybsdnjubxyahjsa
		$a_01_1 = {66 72 47 56 79 6a 6d 48 73 7a 43 } //1 frGVyjmHszC
		$a_01_2 = {6b 67 46 56 43 52 48 6b 68 48 } //1 kgFVCRHkhH
		$a_01_3 = {43 65 6d 55 5a 45 79 49 66 6d 57 } //1 CemUZEyIfmW
		$a_01_4 = {44 74 48 76 69 4b 70 54 76 } //1 DtHviKpTv
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=14
 
}