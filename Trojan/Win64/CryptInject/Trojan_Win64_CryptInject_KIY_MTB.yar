
rule Trojan_Win64_CryptInject_KIY_MTB{
	meta:
		description = "Trojan:Win64/CryptInject.KIY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {44 03 de 48 f7 e1 48 c1 ea 03 48 6b c2 1a 48 2b c8 8a 44 0c 20 42 32 04 13 41 88 02 4c 03 d6 45 3b df 72 cf } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}