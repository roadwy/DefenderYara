
rule Trojan_Win64_BazarLoader_RPR_MTB{
	meta:
		description = "Trojan:Win64/BazarLoader.RPR!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {41 0f b6 0c 00 48 8d 40 01 80 f1 ba ff c2 88 48 ff 81 fa a0 7a 00 00 72 e7 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}