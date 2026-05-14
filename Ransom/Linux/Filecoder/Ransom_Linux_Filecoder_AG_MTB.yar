
rule Ransom_Linux_Filecoder_AG_MTB{
	meta:
		description = "Ransom:Linux/Filecoder.AG!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {52 75 6e 6e 69 6e 67 20 69 6e 20 2f 74 6d 70 2e 20 45 6e 63 72 79 70 74 69 6e 67 20 74 68 65 20 65 6e 74 69 72 65 20 73 79 73 74 65 6d 20 77 69 74 68 20 6b 65 79 } //1 Running in /tmp. Encrypting the entire system with key
		$a_01_1 = {be 7a e3 58 00 48 89 c7 e8 fd 1d 00 00 be 80 e3 58 00 bf a0 cb 5f 00 e8 16 77 05 00 48 8d 45 80 ba 02 00 00 00 be d2 e3 58 00 48 89 c7 e8 26 1e 00 00 48 8d 45 b0 48 8d 95 20 ff ff ff 48 89 d6 48 89 c7 e8 ea 37 09 00 48 8d 55 80 48 8d 45 b0 48 89 d6 48 89 c7 e8 e9 06 00 00 89 c3 48 8d 45 b0 48 89 c7 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}