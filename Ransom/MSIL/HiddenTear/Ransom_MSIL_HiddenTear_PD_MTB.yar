
rule Ransom_MSIL_HiddenTear_PD_MTB{
	meta:
		description = "Ransom:MSIL/HiddenTear.PD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {70 00 68 00 65 00 6e 00 6f 00 6c 00 40 00 4e 00 6f 00 2d 00 72 00 65 00 70 00 6c 00 79 00 2e 00 63 00 6f 00 6d 00 } //01 00  phenol@No-reply.com
		$a_01_1 = {5c 00 44 00 65 00 73 00 6b 00 74 00 6f 00 70 00 5c 00 52 00 45 00 41 00 44 00 5f 00 49 00 54 00 2e 00 74 00 78 00 74 00 } //01 00  \Desktop\READ_IT.txt
		$a_01_2 = {59 00 6f 00 75 00 72 00 20 00 46 00 69 00 6c 00 65 00 73 00 20 00 68 00 61 00 76 00 65 00 20 00 62 00 65 00 65 00 6e 00 20 00 65 00 6e 00 63 00 72 00 79 00 70 00 74 00 65 00 64 00 } //00 00  Your Files have been encrypted
	condition:
		any of ($a_*)
 
}