
rule Trojan_Win64_Lazy_EM_MTB{
	meta:
		description = "Trojan:Win64/Lazy.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {47 1d c1 01 48 83 ec 10 48 31 14 24 48 31 d0 83 44 24 08 28 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}
rule Trojan_Win64_Lazy_EM_MTB_2{
	meta:
		description = "Trojan:Win64/Lazy.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 0f b6 01 80 c0 0e 48 83 c1 01 48 33 d2 4c 0f b6 c0 41 83 e8 01 89 d0 41 3b c0 7f 13 41 83 c0 01 48 63 d0 80 04 11 0d 83 c0 01 41 3b c0 75 f1 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}
rule Trojan_Win64_Lazy_EM_MTB_3{
	meta:
		description = "Trojan:Win64/Lazy.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {4f 70 6f 61 66 69 6f 61 65 6f 61 69 67 64 75 69 67 68 61 64 75 } //1 Opoafioaeoaigduighadu
		$a_01_1 = {52 61 73 39 69 66 75 6f 61 6f 69 66 67 61 6a 64 67 64 69 } //1 Ras9ifuoaoifgajdgdi
		$a_01_2 = {74 69 6d 65 47 65 74 54 69 6d 65 } //1 timeGetTime
		$a_01_3 = {69 6f 76 73 6f 69 67 69 6f 73 65 69 6f 67 69 73 64 6a } //1 iovsoigioseiogisdj
		$a_01_4 = {43 61 6f 61 66 6f 61 77 66 6f 69 61 77 6a 67 69 64 61 6a } //1 Caoafoawfoiawjgidaj
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}