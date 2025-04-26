
rule Trojan_Linux_Sidewalk_D_MTB{
	meta:
		description = "Trojan:Linux/Sidewalk.D!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {83 bb 48 f6 09 00 00 75 ?? 68 ff 00 00 00 8d ?? ?? ?? ?? ?? ?? 56 e8 d8 03 00 00 c6 84 24 ab 01 00 00 00 5d 5a 85 c0 75 ?? 6a 2e 56 e8 38 55 ff ff 5e 5f 85 c0 } //1
		$a_01_1 = {53 57 ff 74 24 64 e8 a8 52 ff ff 8b 44 24 68 01 d8 8b 54 24 6c 29 da 89 c3 f7 db 83 e3 03 29 da } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}