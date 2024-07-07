
rule Trojan_Win64_IcedID_DU_MTB{
	meta:
		description = "Trojan:Win64/IcedID.DU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 05 00 00 "
		
	strings :
		$a_01_0 = {79 74 61 77 75 64 69 6a 73 61 75 68 79 64 6a 61 73 } //10 ytawudijsauhydjas
		$a_01_1 = {66 45 4a 36 57 52 56 62 5a 68 6b } //1 fEJ6WRVbZhk
		$a_01_2 = {53 59 66 63 75 66 4d 38 39 6a } //1 SYfcufM89j
		$a_01_3 = {5a 36 64 50 37 47 36 } //1 Z6dP7G6
		$a_01_4 = {76 6d 54 68 76 49 } //1 vmThvI
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=14
 
}