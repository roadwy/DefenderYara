
rule Ransom_MSIL_Lapsus_A_MTB{
	meta:
		description = "Ransom:MSIL/Lapsus.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {2e 6c 6f 63 6b 65 64 } //1 .locked
		$a_81_1 = {41 6c 65 72 74 61 52 61 6e 73 6f 6d } //1 AlertaRansom
		$a_81_2 = {52 65 61 64 4d 65 2e 74 78 74 } //1 ReadMe.txt
		$a_81_3 = {2e 6f 6e 69 6f 6e } //1 .onion
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}