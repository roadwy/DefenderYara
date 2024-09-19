
rule Ransom_Win32_Basta_JKR_MTB{
	meta:
		description = "Ransom:Win32/Basta.JKR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 4d 0c 8d 76 04 8b 56 fc 2b 54 0e fc 2b d0 8b c2 81 e2 ff ff ff 7f 33 56 fc 23 d3 c1 e8 1f 31 56 fc 83 ef 01 75 d9 } //1
		$a_01_1 = {49 66 20 79 6f 75 20 61 72 65 20 72 65 61 64 69 6e 67 20 74 68 69 73 2c 20 69 74 20 6d 65 61 6e 73 20 77 65 20 68 61 76 65 20 65 6e 63 72 79 70 74 65 64 20 79 6f 75 72 20 64 61 74 61 } //1 If you are reading this, it means we have encrypted your data
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}