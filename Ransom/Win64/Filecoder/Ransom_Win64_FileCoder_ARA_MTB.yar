
rule Ransom_Win64_Filecoder_ARA_MTB{
	meta:
		description = "Ransom:Win64/Filecoder.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {50 61 79 6d 65 6e 74 20 66 6f 72 20 74 68 65 20 64 65 63 72 79 70 74 69 6f 6e } //2 Payment for the decryption
		$a_01_1 = {57 49 4c 4c 20 61 74 74 61 63 6b 20 79 6f 75 20 61 67 61 69 6e } //2 WILL attack you again
		$a_01_2 = {2f 63 32 2f 72 65 63 65 69 76 65 72 } //2 /c2/receiver
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}