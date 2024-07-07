
rule Trojan_Win32_Stealer_NE1_MTB{
	meta:
		description = "Trojan:Win32/Stealer.NE1!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {70 6f 6c 79 20 70 61 73 74 65 20 67 65 74 20 6f 77 6e 65 64 20 62 79 20 62 72 61 69 6e 20 69 73 73 75 65 } //1 poly paste get owned by brain issue
		$a_01_1 = {24 24 24 20 62 65 20 73 6d 61 72 74 2e 20 75 73 65 20 65 61 73 79 63 72 79 70 74 20 24 24 24 } //1 $$$ be smart. use easycrypt $$$
		$a_01_2 = {42 72 6f 6b 65 6e 20 70 72 6f 6d 69 73 65 } //1 Broken promise
		$a_01_3 = {50 72 6f 6d 69 73 65 20 61 6c 72 65 61 64 79 20 73 61 74 69 73 66 69 65 64 } //1 Promise already satisfied
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}