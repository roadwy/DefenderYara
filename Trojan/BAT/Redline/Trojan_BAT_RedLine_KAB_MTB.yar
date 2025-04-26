
rule Trojan_BAT_RedLine_KAB_MTB{
	meta:
		description = "Trojan:BAT/RedLine.KAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {5a 00 41 04 ea 05 2e 04 41 04 53 90 42 04 3a 04 21 09 48 06 3e 04 3e 04 48 06 39 06 2e 09 47 06 d1 05 2d } //1
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_2 = {53 74 72 52 65 76 65 72 73 65 } //1 StrReverse
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}