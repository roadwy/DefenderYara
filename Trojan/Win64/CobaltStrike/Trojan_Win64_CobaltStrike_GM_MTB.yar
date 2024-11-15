
rule Trojan_Win64_CobaltStrike_GM_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.GM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_01_0 = {6d 61 69 6e 2e 78 6f 72 44 65 63 72 79 70 74 } //5 main.xorDecrypt
		$a_01_1 = {6d 61 69 6e 2e 41 65 73 44 65 63 72 79 70 74 43 46 42 } //1 main.AesDecryptCFB
		$a_01_2 = {6d 61 69 6e 2e 72 65 66 75 6e } //1 main.refun
		$a_01_3 = {6d 61 69 6e 2e 72 75 6e } //1 main.run
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=8
 
}