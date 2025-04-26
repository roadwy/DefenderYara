
rule Ransom_Win64_Firedrill_ALJ_MTB{
	meta:
		description = "Ransom:Win64/Firedrill.ALJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_81_0 = {4b 6b 46 73 62 43 42 35 62 33 56 79 49 } //1 KkFsbCB5b3VyI
		$a_81_1 = {66 69 72 65 44 72 69 6c 6c 52 61 6e 73 6f 6d 77 61 72 65 } //1 fireDrillRansomware
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1) >=2
 
}