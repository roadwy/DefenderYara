
rule Trojan_Win64_CryptInject_GN_MTB{
	meta:
		description = "Trojan:Win64/CryptInject.GN!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {ff c0 89 44 24 28 0f b7 44 24 20 8b 4c 24 24 c1 e9 08 8b 54 24 24 c1 e2 18 0b ca 03 c1 8b 4c 24 24 33 c8 8b c1 89 44 24 24 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}