
rule Trojan_Win64_IcedID_DV_MTB{
	meta:
		description = "Trojan:Win64/IcedID.DV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 05 00 00 0a 00 "
		
	strings :
		$a_01_0 = {47 75 61 79 62 73 64 6e 6a 75 62 78 79 61 68 6a 73 61 } //01 00  Guaybsdnjubxyahjsa
		$a_01_1 = {66 72 47 56 79 6a 6d 48 73 7a 43 } //01 00  frGVyjmHszC
		$a_01_2 = {6b 67 46 56 43 52 48 6b 68 48 } //01 00  kgFVCRHkhH
		$a_01_3 = {43 65 6d 55 5a 45 79 49 66 6d 57 } //01 00  CemUZEyIfmW
		$a_01_4 = {44 74 48 76 69 4b 70 54 76 } //00 00  DtHviKpTv
	condition:
		any of ($a_*)
 
}