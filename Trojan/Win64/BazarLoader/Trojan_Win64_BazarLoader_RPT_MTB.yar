
rule Trojan_Win64_BazarLoader_RPT_MTB{
	meta:
		description = "Trojan:Win64/BazarLoader.RPT!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8a 11 88 54 24 21 80 44 24 21 c7 c0 64 24 21 04 } //1
		$a_01_1 = {30 54 24 22 fe 44 24 23 8a 54 24 22 88 10 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}