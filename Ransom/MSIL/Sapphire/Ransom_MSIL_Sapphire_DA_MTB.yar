
rule Ransom_MSIL_Sapphire_DA_MTB{
	meta:
		description = "Ransom:MSIL/Sapphire.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {53 61 70 70 68 69 72 65 20 52 61 6e 73 6f 6d 77 61 72 65 } //1 Sapphire Ransomware
		$a_81_1 = {5f 45 6e 63 72 79 70 74 65 64 24 } //1 _Encrypted$
		$a_81_2 = {41 63 74 69 6f 6e 45 6e 63 72 79 70 74 } //1 ActionEncrypt
		$a_81_3 = {45 6e 63 72 79 70 74 4f 72 44 65 63 72 79 70 74 46 69 6c 65 } //1 EncryptOrDecryptFile
		$a_81_4 = {47 61 63 68 61 4c 69 66 65 5f 55 70 64 61 74 65 2e 70 64 62 } //1 GachaLife_Update.pdb
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}