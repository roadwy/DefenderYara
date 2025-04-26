
rule Trojan_BAT_TeslaCrypt_D_MTB{
	meta:
		description = "Trojan:BAT/TeslaCrypt.D!MTB,SIGNATURE_TYPE_PEHSTR,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {4e 65 78 74 00 53 6c 65 65 70 00 49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //1
		$a_01_1 = {70 72 6f 6a 6e 61 6d 65 } //1 projname
		$a_01_2 = {47 4f 44 6f 66 42 65 61 75 74 79 } //1 GODofBeauty
		$a_01_3 = {41 00 70 00 68 00 72 00 6f 00 64 00 69 00 74 00 65 00 2e 00 64 00 6c 00 6c 00 } //1 Aphrodite.dll
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}