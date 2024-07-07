
rule Trojan_Win64_BazarLoader_RPW_MTB{
	meta:
		description = "Trojan:Win64/BazarLoader.RPW!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 85 c0 74 0b 88 18 ff cf 48 ff c0 85 ff 7f f0 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}