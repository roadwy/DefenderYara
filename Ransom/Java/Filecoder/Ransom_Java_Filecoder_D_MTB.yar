
rule Ransom_Java_Filecoder_D_MTB{
	meta:
		description = "Ransom:Java/Filecoder.D!MTB,SIGNATURE_TYPE_JAVAHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_00_0 = {63 6f 6d 2f 73 65 63 75 72 69 74 79 2f 52 61 6e 73 6f 6d 50 72 6f 63 65 73 73 } //2 com/security/RansomProcess
		$a_00_1 = {53 74 61 72 74 45 6e 63 72 79 70 74 50 72 6f 63 65 73 73 } //1 StartEncryptProcess
		$a_00_2 = {43 72 79 70 74 6f 52 61 6e 73 6f 6d 77 61 72 65 } //2 CryptoRansomware
		$a_00_3 = {45 6e 63 72 79 70 74 46 69 6c 65 } //1 EncryptFile
		$a_00_4 = {72 65 6d 6f 76 65 43 72 79 70 74 6f 67 72 61 70 68 79 52 65 73 74 72 69 63 74 69 6f 6e 73 } //1 removeCryptographyRestrictions
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*1+(#a_00_2  & 1)*2+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=4
 
}