
rule Trojan_BAT_RedLine_RDEX_MTB{
	meta:
		description = "Trojan:BAT/RedLine.RDEX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {61 31 62 32 63 33 64 34 2d 65 35 66 36 2d 37 38 39 30 2d 61 62 63 64 2d 31 32 33 34 35 65 66 36 37 38 39 30 } //2 a1b2c3d4-e5f6-7890-abcd-12345ef67890
		$a_01_1 = {53 74 65 6c 6c 61 72 54 65 63 68 20 53 6f 6c 75 74 69 6f 6e 73 } //1 StellarTech Solutions
		$a_01_2 = {49 6e 6e 6f 76 61 74 69 76 65 20 74 65 63 68 6e 6f 6c 6f 67 69 65 73 20 66 6f 72 20 61 20 63 6f 6e 6e 65 63 74 65 64 20 66 75 74 75 72 65 } //1 Innovative technologies for a connected future
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}