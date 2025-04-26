
rule Trojan_BAT_AsyncRat_CXG_MTB{
	meta:
		description = "Trojan:BAT/AsyncRat.CXG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {54 50 55 58 68 51 68 48 46 4a 61 55 58 70 68 43 52 73 4c 6d 77 6d 4d 62 6b 57 47 51 } //1 TPUXhQhHFJaUXphCRsLmwmMbkWGQ
		$a_01_1 = {78 4e 42 52 59 45 65 70 42 } //1 xNBRYEepB
		$a_01_2 = {6e 48 7a 53 71 45 75 64 61 53 } //1 nHzSqEudaS
		$a_01_3 = {62 62 79 46 4b 61 4c 74 5a } //1 bbyFKaLtZ
		$a_01_4 = {4d 55 4e 44 65 73 73 } //1 MUNDess
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}