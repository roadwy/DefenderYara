
rule Ransom_MSIL_HiddenTear_DO_MTB{
	meta:
		description = "Ransom:MSIL/HiddenTear.DO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {59 6f 75 72 20 70 65 72 73 6f 6e 61 6c 20 66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 } //1 Your personal files have been encrypted
		$a_81_1 = {42 69 74 63 6f 69 6e 20 41 64 64 72 65 73 73 } //1 Bitcoin Address
		$a_81_2 = {72 61 6e 73 6f 6d 2e 6a 70 67 } //1 ransom.jpg
		$a_81_3 = {2e 66 6c 79 70 65 72 } //1 .flyper
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}