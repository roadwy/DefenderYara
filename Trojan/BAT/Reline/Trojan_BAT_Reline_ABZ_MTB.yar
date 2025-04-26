
rule Trojan_BAT_Reline_ABZ_MTB{
	meta:
		description = "Trojan:BAT/Reline.ABZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 05 00 00 "
		
	strings :
		$a_01_0 = {57 97 a2 3f 09 1f 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 61 00 00 00 22 00 00 00 25 00 00 00 6e 00 00 00 09 00 00 00 } //4
		$a_01_1 = {67 65 74 5f 49 73 42 72 6f 77 73 65 72 48 6f 73 74 65 64 } //1 get_IsBrowserHosted
		$a_01_2 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_01_3 = {46 6c 75 73 68 46 69 6e 61 6c 42 6c 6f 63 6b } //1 FlushFinalBlock
		$a_01_4 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=8
 
}