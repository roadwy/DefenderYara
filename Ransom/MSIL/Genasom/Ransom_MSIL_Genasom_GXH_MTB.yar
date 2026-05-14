
rule Ransom_MSIL_Genasom_GXH_MTB{
	meta:
		description = "Ransom:MSIL/Genasom.GXH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 05 00 00 "
		
	strings :
		$a_03_0 = {25 72 62 01 00 70 6f ?? 00 00 0a 25 72 7c 01 00 70 6f ?? 00 00 0a 25 17 6f ?? 00 00 0a } //5
		$a_01_1 = {67 65 74 5f 65 6e 63 72 79 70 74 69 6f 6e 5f 6b 65 79 } //1 get_encryption_key
		$a_01_2 = {43 72 65 61 74 65 52 61 6e 73 6f 6d 4e 6f 74 65 } //1 CreateRansomNote
		$a_01_3 = {44 69 73 61 62 6c 65 52 65 63 6f 76 65 72 79 } //1 DisableRecovery
		$a_01_4 = {45 6e 63 72 79 70 74 44 69 72 65 63 74 6f 72 79 } //1 EncryptDirectory
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=9
 
}