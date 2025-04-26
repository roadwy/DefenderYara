
rule Trojan_BAT_LummaC_WSAA_MTB{
	meta:
		description = "Trojan:BAT/LummaC.WSAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 06 00 00 "
		
	strings :
		$a_01_0 = {4c 50 69 6f 6e 65 65 72 69 6e 67 20 74 68 65 20 66 75 74 75 72 65 20 6f 66 20 74 65 63 68 6e 6f 6c 6f 67 79 20 77 69 74 68 20 69 6e 6e 6f 76 61 74 69 76 65 20 61 6e 64 20 65 66 66 69 63 69 65 6e 74 20 73 6f 6c 75 74 69 6f 6e 73 2e } //2 LPioneering the future of technology with innovative and efficient solutions.
		$a_01_1 = {45 6c 65 6d 65 6e 74 20 49 4f 20 49 6e 6e 6f 76 61 74 69 6f 6e 73 20 49 6e 63 2e } //2 Element IO Innovations Inc.
		$a_01_2 = {45 6c 65 6d 65 6e 74 20 49 4f 20 41 64 76 61 6e 63 65 64 20 53 75 69 74 65 } //1 Element IO Advanced Suite
		$a_01_3 = {45 6c 65 6d 65 6e 74 20 49 4f 20 49 6e 6e 6f 76 61 74 69 6f 6e 73 20 54 72 61 64 65 6d 61 72 6b } //1 Element IO Innovations Trademark
		$a_01_4 = {24 30 63 37 38 34 66 30 32 2d 65 30 66 35 2d 34 33 61 31 2d 39 34 37 61 2d 61 65 61 32 31 38 66 64 33 31 64 66 } //1 $0c784f02-e0f5-43a1-947a-aea218fd31df
		$a_01_5 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=8
 
}