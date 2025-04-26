
rule Trojan_BAT_CrypterX_RDA_MTB{
	meta:
		description = "Trojan:BAT/CrypterX.RDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {39 63 30 66 37 30 36 30 2d 33 62 36 61 2d 34 39 35 65 2d 61 38 32 61 2d 34 65 64 30 39 63 62 39 38 65 34 38 } //1 9c0f7060-3b6a-495e-a82a-4ed09cb98e48
		$a_01_1 = {44 61 74 61 50 72 6f 74 65 63 74 69 6f 6e 53 63 6f 70 65 } //1 DataProtectionScope
		$a_01_2 = {66 61 74 68 65 72 } //1 father
		$a_01_3 = {50 72 6f 74 65 63 74 4d 65 } //1 ProtectMe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}