
rule Ransom_MSIL_CryptoLocker_DH_MTB{
	meta:
		description = "Ransom:MSIL/CryptoLocker.DH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,37 00 37 00 06 00 00 "
		
	strings :
		$a_81_0 = {50 6f 76 6c 73 6f 6d 77 61 72 65 } //40 Povlsomware
		$a_81_1 = {52 61 73 6f 6d 77 61 72 65 32 2e 5f 30 } //40 Rasomware2._0
		$a_81_2 = {54 6f 42 61 73 65 36 34 53 74 72 69 6e 67 } //10 ToBase64String
		$a_81_3 = {5f 45 6e 63 72 79 70 74 65 64 24 } //10 _Encrypted$
		$a_81_4 = {50 61 79 4d 33 } //5 PayM3
		$a_81_5 = {55 6d 46 7a 62 32 31 33 59 58 4a 6c 4d 69 34 77 4a 41 3d 3d } //5 UmFzb213YXJlMi4wJA==
	condition:
		((#a_81_0  & 1)*40+(#a_81_1  & 1)*40+(#a_81_2  & 1)*10+(#a_81_3  & 1)*10+(#a_81_4  & 1)*5+(#a_81_5  & 1)*5) >=55
 
}
rule Ransom_MSIL_CryptoLocker_DH_MTB_2{
	meta:
		description = "Ransom:MSIL/CryptoLocker.DH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {44 65 63 72 79 70 74 6f 72 2e 65 78 65 } //1 Decryptor.exe
		$a_81_1 = {4e 61 6d 61 73 74 65 55 6e 6c 6f 63 6b } //1 NamasteUnlock
		$a_81_2 = {67 65 74 5f 43 75 72 72 65 6e 74 44 6f 6d 61 69 6e } //1 get_CurrentDomain
		$a_81_3 = {44 65 63 6f 64 65 57 69 74 68 4d 61 74 63 68 42 79 74 65 } //1 DecodeWithMatchByte
		$a_81_4 = {54 6f 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 ToBase64String
		$a_81_5 = {43 6f 6e 66 75 73 65 72 45 78 } //1 ConfuserEx
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}