
rule Trojan_BAT_RedLine_RDEY_MTB{
	meta:
		description = "Trojan:BAT/RedLine.RDEY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {65 66 64 64 35 38 37 64 2d 34 31 64 35 2d 34 34 32 65 2d 38 66 39 34 2d 65 30 61 33 31 65 35 62 65 39 37 66 } //2 efdd587d-41d5-442e-8f94-e0a31e5be97f
		$a_01_1 = {48 75 61 77 65 69 20 53 68 61 72 65 } //1 Huawei Share
		$a_01_2 = {53 75 69 74 65 20 50 72 6f } //1 Suite Pro
		$a_01_3 = {4c 65 61 64 69 6e 67 2d 65 64 67 65 20 73 6f 6c 75 74 69 6f 6e 73 20 66 6f 72 20 61 20 63 6f 6e 6e 65 63 74 65 64 20 77 6f 72 6c 64 } //1 Leading-edge solutions for a connected world
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}