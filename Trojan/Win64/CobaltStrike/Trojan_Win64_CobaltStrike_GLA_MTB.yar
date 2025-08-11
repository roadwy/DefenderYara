
rule Trojan_Win64_CobaltStrike_GLA_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.GLA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 05 00 00 "
		
	strings :
		$a_01_0 = {45 0f b6 7c 01 02 48 ff c6 45 31 e7 45 31 ef } //4
		$a_01_1 = {44 88 7c 1e ff 48 ff c0 4c 39 d8 } //4
		$a_01_2 = {61 6c 6d 6f 75 6e 61 68 2f 67 6f 2d 62 75 65 6e 61 2d 63 6c 72 } //1 almounah/go-buena-clr
		$a_01_3 = {62 75 65 6e 61 76 69 6c 6c 61 67 65 } //1 buenavillage
		$a_01_4 = {47 6f 20 62 75 69 6c 64 20 49 44 3a } //1 Go build ID:
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*4+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=11
 
}