
rule Trojan_Win64_BazarLoader_RPI_MTB{
	meta:
		description = "Trojan:Win64/BazarLoader.RPI!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {40 88 6c 24 46 c7 44 24 6c 42 00 00 00 8a 54 24 37 80 ea b4 80 c2 01 80 c2 b4 88 54 24 37 c7 44 24 68 6a 00 00 00 8a 54 24 46 48 8b 4c 24 38 88 11 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}