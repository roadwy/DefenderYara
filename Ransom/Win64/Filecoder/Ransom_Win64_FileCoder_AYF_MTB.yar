
rule Ransom_Win64_FileCoder_AYF_MTB{
	meta:
		description = "Ransom:Win64/FileCoder.AYF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {56 72 75 6e 6e 65 72 2e 70 64 62 } //2 Vrunner.pdb
		$a_01_1 = {59 6f 75 72 20 63 6f 6d 70 75 74 65 72 20 68 61 73 20 62 65 65 6e 20 64 65 73 74 72 6f 79 65 64 20 62 79 20 56 72 75 6e 6e 65 72 } //1 Your computer has been destroyed by Vrunner
		$a_01_2 = {59 6f 75 20 63 61 6e 20 67 65 74 20 74 68 65 20 6b 65 79 20 62 79 20 70 61 79 69 6e 67 20 74 68 65 20 72 61 6e 73 6f 6d } //1 You can get the key by paying the ransom
		$a_01_3 = {49 20 68 61 76 65 20 6e 6f 20 6d 6f 6e 65 79 2c 20 49 20 72 65 73 74 61 72 74 20 6e 6f 77 2c 20 61 74 20 6c 65 61 73 74 20 74 68 65 20 63 6f 6d 70 75 74 65 72 20 63 61 6e 20 73 74 69 6c 6c 20 75 73 65 20 69 74 } //1 I have no money, I restart now, at least the computer can still use it
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}