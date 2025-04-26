
rule Ransom_Win32_Play_AA_MTB{
	meta:
		description = "Ransom:Win32/Play.AA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {4e 45 54 57 4f 52 4b 20 54 48 52 45 41 44 20 53 54 41 52 54 20 45 4e 43 52 59 50 54 49 4f 4e 3a } //1 NETWORK THREAD START ENCRYPTION:
		$a_01_1 = {45 6e 63 72 79 70 74 4c 6f 63 61 6c 41 6e 64 4e 65 74 77 6f 72 6b 20 2d 31 } //1 EncryptLocalAndNetwork -1
		$a_01_2 = {49 6e 69 74 50 72 6f 76 69 64 65 72 73 49 6d 70 6f 72 74 50 75 62 6c 69 63 4b 65 79 20 2d 31 20 43 52 49 54 49 43 41 4c } //1 InitProvidersImportPublicKey -1 CRITICAL
		$a_01_3 = {73 65 63 6f 6e 64 20 73 74 65 70 20 65 6e 63 72 79 70 74 69 6f 6e } //1 second step encryption
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}