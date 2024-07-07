
rule Ransom_MSIL_Clarity_DA_MTB{
	meta:
		description = "Ransom:MSIL/Clarity.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {57 61 6e 6e 61 43 6c 61 72 69 74 79 } //1 WannaClarity
		$a_81_1 = {54 6f 20 64 65 63 72 79 70 74 20 79 6f 75 72 20 66 69 6c 65 73 20 79 6f 75 20 6e 65 65 64 20 74 6f 20 70 75 72 63 68 61 73 65 20 61 6e 20 64 65 63 72 79 70 74 69 6f 6e 20 6b 65 79 2e } //1 To decrypt your files you need to purchase an decryption key.
		$a_81_2 = {2e 63 6c 61 72 69 74 79 } //1 .clarity
		$a_81_3 = {46 69 6e 69 73 68 65 64 21 2c 20 63 6c 6f 73 65 20 69 74 20 77 69 74 68 20 79 6f 75 72 20 54 61 73 6b 6d 61 6e 61 67 65 72 21 } //1 Finished!, close it with your Taskmanager!
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}