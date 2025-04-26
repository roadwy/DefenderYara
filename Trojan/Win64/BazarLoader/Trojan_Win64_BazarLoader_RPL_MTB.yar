
rule Trojan_Win64_BazarLoader_RPL_MTB{
	meta:
		description = "Trojan:Win64/BazarLoader.RPL!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 53 01 c0 e2 03 8a 0b 80 e1 07 0a d1 c0 e2 03 8a 43 ff 24 07 0a d0 43 88 14 08 49 ff c0 48 8d 5b 03 49 81 f8 00 04 00 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}