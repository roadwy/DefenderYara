
rule Trojan_Win64_DCRat_RPA_MTB{
	meta:
		description = "Trojan:Win64/DCRat.RPA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,6e 00 6e 00 02 00 00 "
		
	strings :
		$a_01_0 = {59 48 6f 74 5a 70 53 4e 56 56 7a 39 69 4c 56 69 66 6a 39 67 47 6a 4c 75 38 } //100 YHotZpSNVVz9iLVifj9gGjLu8
		$a_01_1 = {5f 43 6f 72 45 00 78 65 4d 61 69 6e 00 6d 00 73 63 6f 72 65 65 2e 64 43 6c } //10
	condition:
		((#a_01_0  & 1)*100+(#a_01_1  & 1)*10) >=110
 
}