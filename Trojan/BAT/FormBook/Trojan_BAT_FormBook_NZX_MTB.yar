
rule Trojan_BAT_FormBook_NZX_MTB{
	meta:
		description = "Trojan:BAT/FormBook.NZX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {56 35 37 37 35 52 34 4f 37 41 47 39 42 35 38 39 41 44 35 48 35 43 } //1 V5775R4O7AG9B589AD5H5C
		$a_81_1 = {4b 6f 6f 6c 61 6e } //1 Koolan
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_01_3 = {52 69 6a 6e 64 61 65 6c 4d 61 6e 61 67 65 64 } //1 RijndaelManaged
		$a_01_4 = {47 65 74 4f 62 6a 65 63 74 } //1 GetObject
		$a_01_5 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggableAttribute
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}