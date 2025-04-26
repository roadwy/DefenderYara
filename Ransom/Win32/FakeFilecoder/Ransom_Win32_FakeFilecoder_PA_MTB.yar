
rule Ransom_Win32_FakeFilecoder_PA_MTB{
	meta:
		description = "Ransom:Win32/FakeFilecoder.PA!MTB,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {44 00 6f 00 6e 00 74 00 20 00 74 00 72 00 79 00 20 00 74 00 6f 00 20 00 6b 00 69 00 6c 00 6c 00 20 00 6f 00 72 00 20 00 72 00 65 00 6d 00 6f 00 76 00 65 00 20 00 74 00 68 00 65 00 20 00 43 00 61 00 6d 00 79 00 20 00 74 00 72 00 6f 00 6a 00 61 00 6e 00 2c 00 20 00 6f 00 72 00 20 00 79 00 6f 00 75 00 72 00 20 00 66 00 69 00 6c 00 65 00 73 00 20 00 61 00 72 00 65 00 20 00 64 00 65 00 6c 00 65 00 74 00 65 00 64 00 } //1 Dont try to kill or remove the Camy trojan, or your files are deleted
		$a_01_1 = {43 00 79 00 6d 00 61 00 5f 00 52 00 61 00 6e 00 73 00 6f 00 6d 00 } //1 Cyma_Ransom
		$a_01_2 = {4c 00 6f 00 67 00 69 00 6e 00 54 00 6f 00 45 00 6e 00 63 00 72 00 79 00 70 00 74 00 } //1 LoginToEncrypt
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}