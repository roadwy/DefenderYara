
rule Backdoor_BAT_SpyGate_KA_MTB{
	meta:
		description = "Backdoor:BAT/SpyGate.KA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {4d 00 2a 00 34 00 43 00 2a 00 77 00 2a 00 67 } //1
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_2 = {53 74 72 52 65 76 65 72 73 65 } //1 StrReverse
		$a_01_3 = {52 65 70 6c 61 63 65 } //1 Replace
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}