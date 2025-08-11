
rule Trojan_Win64_BlackWidow_BG_MTB{
	meta:
		description = "Trojan:Win64/BlackWidow.BG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {48 31 d2 49 f7 f6 45 8a 2c 11 } //1
		$a_01_1 = {49 f7 e3 49 01 c7 } //1
		$a_01_2 = {44 30 2c 0f } //1 い༬
		$a_01_3 = {79 47 37 42 5e 3e 53 57 78 31 35 32 33 59 29 32 75 2b } //2 yG7B^>SWx1523Y)2u+
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*2) >=5
 
}