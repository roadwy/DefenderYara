
rule Trojan_Win64_Lazy_ZZ_MTB{
	meta:
		description = "Trojan:Win64/Lazy.ZZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {41 0f b7 0c 11 66 33 cb 66 89 0a 48 8d 52 02 49 83 e8 01 75 } //1
		$a_81_1 = {68 64 66 7a 70 79 73 76 70 7a 69 6d 6f 72 68 6b } //1 hdfzpysvpzimorhk
	condition:
		((#a_01_0  & 1)*1+(#a_81_1  & 1)*1) >=2
 
}