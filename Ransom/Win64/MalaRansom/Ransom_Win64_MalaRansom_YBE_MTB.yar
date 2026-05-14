
rule Ransom_Win64_MalaRansom_YBE_MTB{
	meta:
		description = "Ransom:Win64/MalaRansom.YBE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {4d 61 6c 61 20 52 61 6e 73 6f 6d } //1 Mala Ransom
		$a_01_1 = {79 6f 75 20 64 6f 20 6e 6f 74 20 68 61 76 65 20 74 6f 20 70 61 79 20 75 73 } //1 you do not have to pay us
		$a_01_2 = {64 65 63 72 79 70 74 69 6f 6e } //1 decryption
		$a_01_3 = {65 6e 63 72 79 70 74 65 64 } //1 encrypted
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}