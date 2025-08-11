
rule Ransom_MSIL_Crypticware_PA_MTB{
	meta:
		description = "Ransom:MSIL/Crypticware.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {43 00 72 00 79 00 70 00 74 00 69 00 63 00 77 00 61 00 72 00 65 00 } //1 Crypticware
		$a_01_1 = {53 69 6d 70 6c 65 58 4f 52 45 6e 63 72 79 70 74 69 6f 6e } //1 SimpleXOREncryption
		$a_01_2 = {59 00 6f 00 75 00 72 00 20 00 69 00 6d 00 70 00 6f 00 72 00 74 00 61 00 6e 00 74 00 20 00 66 00 69 00 6c 00 65 00 73 00 20 00 68 00 61 00 73 00 20 00 62 00 65 00 65 00 6e 00 20 00 65 00 6e 00 63 00 72 00 79 00 70 00 74 00 65 00 64 00 20 00 77 00 69 00 74 00 68 00 20 00 43 00 72 00 79 00 70 00 74 00 69 00 63 00 77 00 61 00 72 00 65 00 2e 00 } //3 Your important files has been encrypted with Crypticware.
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*3) >=5
 
}