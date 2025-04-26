
rule Ransom_MSIL_Darkside_SK_MTB{
	meta:
		description = "Ransom:MSIL/Darkside.SK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_81_0 = {42 75 74 20 79 6f 75 20 63 61 6e 20 72 65 73 74 6f 72 65 20 65 76 65 72 79 74 68 69 6e 67 20 62 79 20 70 75 72 63 68 61 73 69 6e 67 20 61 20 73 70 65 63 69 61 6c 20 70 72 6f 67 72 61 6d 20 66 72 6f 6d 20 75 73 20 2d 20 75 6e 69 76 65 72 73 61 6c 20 64 65 63 72 79 70 74 6f 72 } //1 But you can restore everything by purchasing a special program from us - universal decryptor
		$a_81_1 = {44 4f 20 4e 4f 54 20 4d 4f 44 49 46 59 20 6f 72 20 74 72 79 20 74 6f 20 52 45 43 4f 56 45 52 20 61 6e 79 20 66 69 6c 65 73 20 79 6f 75 72 73 65 6c 66 2e 20 57 65 20 57 49 4c 4c 20 4e 4f 54 20 62 65 20 61 62 6c 65 20 74 6f 20 52 45 53 54 4f 52 45 20 74 68 65 6d 2e } //1 DO NOT MODIFY or try to RECOVER any files yourself. We WILL NOT be able to RESTORE them.
		$a_81_2 = {57 65 20 67 75 61 72 61 6e 74 65 65 20 74 6f 20 64 65 63 72 79 70 74 20 6f 6e 65 20 66 69 6c 65 20 66 6f 72 20 66 72 65 65 2e 20 47 6f 20 74 6f 20 74 68 65 20 73 69 74 65 20 61 6e 64 20 63 6f 6e 74 61 63 74 20 75 73 2e } //1 We guarantee to decrypt one file for free. Go to the site and contact us.
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}