
rule Trojan_Win32_VBObfuse_SA_MTB{
	meta:
		description = "Trojan:Win32/VBObfuse.SA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {49 00 43 00 73 00 4c 00 35 00 6a 00 66 00 34 00 72 00 4a 00 4d 00 6d 00 38 00 61 00 66 00 52 00 36 00 33 00 72 00 35 00 70 00 41 00 4b 00 41 00 50 00 48 00 79 00 34 00 55 00 34 00 4d 00 7a 00 37 00 44 00 4b 00 59 00 6a 00 31 00 32 00 36 00 } //1 ICsL5jf4rJMm8afR63r5pAKAPHy4U4Mz7DKYj126
		$a_01_1 = {42 00 72 00 55 00 75 00 30 00 61 00 65 00 68 00 79 00 30 00 44 00 47 00 4f 00 5a 00 77 00 4c 00 46 00 6e 00 48 00 6f 00 7a 00 45 00 6b 00 6f 00 36 00 4a 00 61 00 53 00 56 00 41 00 55 00 30 00 4a 00 55 00 30 00 4b 00 43 00 62 00 41 00 35 00 31 00 32 00 35 00 } //1 BrUu0aehy0DGOZwLFnHozEko6JaSVAU0JU0KCbA5125
		$a_01_2 = {69 00 6c 00 76 00 63 00 37 00 36 00 } //1 ilvc76
		$a_01_3 = {47 00 31 00 38 00 55 00 56 00 4a 00 53 00 62 00 35 00 39 00 } //1 G18UVJSb59
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}