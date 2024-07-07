
rule Ransom_MSIL_LockBIT_DC_MTB{
	meta:
		description = "Ransom:MSIL/LockBIT.DC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 "
		
	strings :
		$a_01_0 = {4c 6f 63 6b 42 49 54 } //1 LockBIT
		$a_01_1 = {45 6e 63 72 79 70 74 } //1 Encrypt
		$a_01_2 = {52 65 61 64 41 6c 6c 42 79 74 65 73 } //1 ReadAllBytes
		$a_01_3 = {47 65 74 4c 6f 67 69 63 61 6c 44 72 69 76 65 73 } //1 GetLogicalDrives
		$a_01_4 = {47 65 74 44 69 72 65 63 74 6f 72 69 65 73 } //1 GetDirectories
		$a_01_5 = {47 65 74 46 69 6c 65 73 } //1 GetFiles
		$a_01_6 = {45 78 63 65 70 74 69 6f 6e } //1 Exception
		$a_01_7 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_8 = {54 6f 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 ToBase64String
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=9
 
}