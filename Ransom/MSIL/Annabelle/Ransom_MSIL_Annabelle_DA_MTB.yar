
rule Ransom_MSIL_Annabelle_DA_MTB{
	meta:
		description = "Ransom:MSIL/Annabelle.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {66 69 6c 65 45 6e 63 72 79 70 74 65 64 } //1 fileEncrypted
		$a_81_1 = {62 79 74 65 73 54 6f 42 65 45 6e 63 72 79 70 74 65 64 } //1 bytesToBeEncrypted
		$a_81_2 = {46 72 69 64 61 79 50 72 6f 6a 65 63 74 2e 50 72 6f 70 65 72 74 69 65 73 } //1 FridayProject.Properties
		$a_81_3 = {47 65 74 54 65 6d 70 50 61 74 68 } //1 GetTempPath
		$a_81_4 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}
rule Ransom_MSIL_Annabelle_DA_MTB_2{
	meta:
		description = "Ransom:MSIL/Annabelle.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {41 6e 6e 61 62 65 6c 6c 65 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //1 Annabelle.Resources.resources
		$a_81_1 = {41 6e 6e 61 62 65 6c 6c 65 2e 65 78 65 } //1 Annabelle.exe
		$a_81_2 = {43 72 65 61 74 65 45 6e 63 72 79 70 74 6f 72 } //1 CreateEncryptor
		$a_81_3 = {47 65 74 4c 6f 67 69 63 61 6c 44 72 69 76 65 73 } //1 GetLogicalDrives
		$a_81_4 = {41 63 74 69 6f 6e 45 6e 63 72 79 70 74 } //1 ActionEncrypt
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}