
rule Trojan_BAT_AgentTesla_PSBU_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PSBU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 07 00 00 "
		
	strings :
		$a_01_0 = {57 ff a3 3f 09 0f 00 00 00 fa 01 33 00 16 00 00 01 00 00 00 bf 00 00 00 77 01 00 00 27 06 00 00 98 07 00 00 fc 0b 00 00 } //5
		$a_01_1 = {43 69 70 68 65 72 4d 6f 64 65 } //1 CipherMode
		$a_01_2 = {53 79 6d 6d 65 74 72 69 63 41 6c 67 6f 72 69 74 68 6d } //1 SymmetricAlgorithm
		$a_01_3 = {49 43 72 79 70 74 6f 54 72 61 6e 73 66 6f 72 6d } //1 ICryptoTransform
		$a_01_4 = {48 61 73 68 41 6c 67 6f 72 69 74 68 6d } //1 HashAlgorithm
		$a_01_5 = {44 65 72 69 76 65 42 79 74 65 73 } //1 DeriveBytes
		$a_01_6 = {53 79 73 74 65 6d 2e 53 65 63 75 72 69 74 79 2e 43 72 79 70 74 6f 67 72 61 70 68 79 } //1 System.Security.Cryptography
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=11
 
}