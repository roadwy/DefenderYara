
rule Trojan_Win64_IcedID_MAI_MTB{
	meta:
		description = "Trojan:Win64/IcedID.MAI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {52 75 6e 4f 62 6a 65 63 74 } //1 RunObject
		$a_01_1 = {53 66 31 30 53 47 37 32 4c 66 } //1 Sf10SG72Lf
		$a_01_2 = {62 4e 6b 32 4d 61 79 68 38 } //1 bNk2Mayh8
		$a_01_3 = {72 4d 77 36 63 6a 76 } //1 rMw6cjv
		$a_01_4 = {77 79 38 73 71 76 38 69 77 } //1 wy8sqv8iw
		$a_01_5 = {47 6b 68 6b 67 62 } //1 Gkhkgb
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}