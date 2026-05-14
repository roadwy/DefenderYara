
rule Ransom_Win64_Cerber_ARAX_MTB{
	meta:
		description = "Ransom:Win64/Cerber.ARAX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {2e 77 63 72 79 } //2 .wcry
		$a_01_1 = {42 69 74 63 6f 69 6e 20 74 6f 20 74 68 69 73 20 41 64 64 72 65 73 73 } //2 Bitcoin to this Address
		$a_01_2 = {66 69 6c 65 73 20 61 72 65 20 65 6e 63 72 79 70 74 65 64 } //2 files are encrypted
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}