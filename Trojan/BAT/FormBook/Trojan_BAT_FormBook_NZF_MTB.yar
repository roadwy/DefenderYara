
rule Trojan_BAT_FormBook_NZF_MTB{
	meta:
		description = "Trojan:BAT/FormBook.NZF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 05 00 00 "
		
	strings :
		$a_81_0 = {68 74 74 70 3a 2f 2f 39 31 2e 39 32 2e 32 35 34 2e 31 37 38 2f 73 61 70 68 69 72 65 2f 46 6a 76 73 65 67 6a 76 6c 76 66 2e 76 64 66 } //3 http://91.92.254.178/saphire/Fjvsegjvlvf.vdf
		$a_81_1 = {52 65 61 64 41 73 42 79 74 65 41 72 72 61 79 41 73 79 6e 63 } //1 ReadAsByteArrayAsync
		$a_81_2 = {47 65 74 41 73 79 6e 63 } //1 GetAsync
		$a_81_3 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_81_4 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_81_0  & 1)*3+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=7
 
}