
rule Ransom_MSIL_IncRansom_YAD_MTB{
	meta:
		description = "Ransom:MSIL/IncRansom.YAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 04 00 00 "
		
	strings :
		$a_01_0 = {72 61 6e 73 6f 6d 65 77 61 72 65 2e 70 73 31 } //10 ransomeware.ps1
		$a_01_1 = {46 49 4c 45 53 20 48 41 56 45 20 42 45 45 4e 20 45 4e 43 52 59 50 54 45 44 } //5 FILES HAVE BEEN ENCRYPTED
		$a_01_2 = {65 6e 63 72 79 70 74 65 64 20 77 69 74 68 20 6d 69 6c 69 74 61 72 79 2d 67 72 61 64 65 20 65 6e 63 72 79 70 74 69 6f 6e } //5 encrypted with military-grade encryption
		$a_01_3 = {50 41 59 20 54 48 45 20 52 41 4e 53 4f 4d } //1 PAY THE RANSOM
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*5+(#a_01_2  & 1)*5+(#a_01_3  & 1)*1) >=21
 
}