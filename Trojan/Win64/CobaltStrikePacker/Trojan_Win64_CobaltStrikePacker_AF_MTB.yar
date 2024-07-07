
rule Trojan_Win64_CobaltStrikePacker_AF_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrikePacker.AF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 89 c3 31 c0 48 89 c2 83 e2 07 8a 54 15 00 32 14 07 88 14 03 48 ff c0 39 c6 7f e9 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}