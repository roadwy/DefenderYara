
rule Ransom_Win32_CylanceCryptor_ND_MTB{
	meta:
		description = "Ransom:Win32/CylanceCryptor.ND!MTB,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {0f b6 86 10 07 42 00 50 68 58 12 42 00 57 ff d3 46 83 c4 0c 83 c7 02 83 fe 08 7c e4 } //1
		$a_01_1 = {0f b6 03 8d 5b 01 8b ce c1 e6 08 c1 e9 18 33 c8 33 34 8d 10 ef 41 00 83 ea 01 75 e4 } //1
		$a_01_2 = {59 6f 75 72 20 44 65 63 72 79 70 74 69 6f 6e 20 49 44 3a } //1 Your Decryption ID:
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}