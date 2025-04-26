
rule Trojan_BAT_LummaC_WQAA_MTB{
	meta:
		description = "Trojan:BAT/LummaC.WQAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 06 00 00 "
		
	strings :
		$a_01_0 = {4b 52 65 76 6f 6c 75 74 69 6f 6e 69 7a 69 6e 67 20 72 65 6e 65 77 61 62 6c 65 20 65 6e 65 72 67 79 20 77 69 74 68 20 61 64 76 61 6e 63 65 64 20 73 6f 6c 61 72 20 61 6e 64 20 73 74 6f 72 61 67 65 20 73 6f 6c 75 74 69 6f 6e 73 2e } //2 KRevolutionizing renewable energy with advanced solar and storage solutions.
		$a_01_1 = {48 65 6c 69 6f 43 6f 72 65 20 45 6e 65 72 67 79 20 53 75 69 74 65 } //2 HelioCore Energy Suite
		$a_01_2 = {48 65 6c 69 6f 43 6f 72 65 20 49 6e 6e 6f 76 61 74 69 6f 6e 73 20 49 6e 63 2e } //1 HelioCore Innovations Inc.
		$a_01_3 = {48 65 6c 69 6f 43 6f 72 65 20 49 6e 6e 6f 76 61 74 69 6f 6e 73 20 54 72 61 64 65 6d 61 72 6b } //1 HelioCore Innovations Trademark
		$a_01_4 = {24 62 37 63 38 64 39 65 30 2d 66 31 61 32 2d 34 33 32 34 2d 62 64 35 65 2d 36 37 38 39 30 61 62 63 64 65 66 30 } //1 $b7c8d9e0-f1a2-4324-bd5e-67890abcdef0
		$a_01_5 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=8
 
}