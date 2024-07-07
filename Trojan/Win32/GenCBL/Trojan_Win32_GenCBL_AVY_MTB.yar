
rule Trojan_Win32_GenCBL_AVY_MTB{
	meta:
		description = "Trojan:Win32/GenCBL.AVY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {42 65 6e 51 20 5a 6f 77 69 65 20 58 4c 32 34 31 31 50 20 32 34 } //1 BenQ Zowie XL2411P 24
		$a_81_1 = {32 31 30 39 30 37 31 32 32 33 32 30 } //1 210907122320
		$a_81_2 = {33 31 30 39 30 38 31 32 32 33 32 30 } //1 310908122320
		$a_81_3 = {47 72 65 61 74 65 72 20 4d 61 6e 63 68 65 73 74 65 72 } //1 Greater Manchester
		$a_81_4 = {4e 65 77 20 4a 65 72 73 65 79 } //1 New Jersey
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}