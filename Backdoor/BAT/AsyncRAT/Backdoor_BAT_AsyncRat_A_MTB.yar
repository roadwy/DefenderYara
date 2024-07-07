
rule Backdoor_BAT_AsyncRat_A_MTB{
	meta:
		description = "Backdoor:BAT/AsyncRat.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {0a 1f 1a 28 90 01 03 0a 72 53 00 00 70 28 90 01 03 0a 17 28 90 01 03 0a 7e 90 01 03 0a 02 72 63 00 00 70 28 90 01 03 06 17 6f 90 01 03 0a 72 c5 00 00 70 1f 1a 90 00 } //1
		$a_81_1 = {43 4f 4d 20 53 75 72 72 6f 67 61 74 65 } //1 COM Surrogate
		$a_81_2 = {52 65 70 6c 61 63 65 } //1 Replace
		$a_81_3 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggableAttribute
		$a_81_4 = {53 6c 65 65 70 } //1 Sleep
	condition:
		((#a_03_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}