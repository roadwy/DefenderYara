
rule Ransom_Win64_Basta_SAB_MTB{
	meta:
		description = "Ransom:Win64/Basta.SAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {69 6e 73 74 72 75 63 74 69 6f 6e 73 5f 72 65 61 64 5f 6d 65 2e 74 78 74 } //1 instructions_read_me.txt
		$a_01_1 = {59 6f 75 72 20 6e 65 74 77 6f 72 6b 20 68 61 73 20 62 65 65 6e 20 62 72 65 61 63 68 65 64 20 61 6e 64 20 61 6c 6c 20 64 61 74 61 20 77 61 73 20 65 6e 63 72 79 70 74 65 64 } //1 Your network has been breached and all data was encrypted
		$a_01_2 = {6b 69 6c 6c 73 65 72 76 69 63 65 73 } //1 killservices
		$a_01_3 = {6f 6e 69 6f 6e } //1 onion
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}