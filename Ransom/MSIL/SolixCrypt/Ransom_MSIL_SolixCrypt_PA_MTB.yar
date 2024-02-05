
rule Ransom_MSIL_SolixCrypt_PA_MTB{
	meta:
		description = "Ransom:MSIL/SolixCrypt.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {79 00 6f 00 75 00 72 00 5f 00 69 00 6d 00 61 00 67 00 65 00 5f 00 6e 00 61 00 6d 00 65 00 2e 00 6a 00 70 00 67 00 } //01 00 
		$a_01_1 = {2e 00 53 00 6f 00 6c 00 69 00 78 00 } //01 00 
		$a_01_2 = {59 00 6f 00 75 00 72 00 20 00 66 00 69 00 6c 00 65 00 73 00 20 00 68 00 61 00 76 00 65 00 20 00 62 00 65 00 65 00 6e 00 20 00 65 00 6e 00 63 00 72 00 79 00 70 00 74 00 65 00 64 00 21 00 } //00 00 
	condition:
		any of ($a_*)
 
}