
rule Trojan_Win64_CobaltStrike_CCJL_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.CCJL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 05 00 00 "
		
	strings :
		$a_01_0 = {4f 4f 70 57 45 38 44 44 } //5 OOpWE8DD
		$a_01_1 = {51 74 4f 66 31 33 38 4d } //1 QtOf138M
		$a_01_2 = {55 50 68 4b 67 61 } //1 UPhKga
		$a_01_3 = {57 6a 59 42 6c 32 34 31 30 } //1 WjYBl2410
		$a_01_4 = {5a 57 6a 39 30 45 7a } //1 ZWj90Ez
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=9
 
}