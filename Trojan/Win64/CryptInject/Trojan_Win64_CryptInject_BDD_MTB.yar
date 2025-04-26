
rule Trojan_Win64_CryptInject_BDD_MTB{
	meta:
		description = "Trojan:Win64/CryptInject.BDD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {44 30 1c 0f c4 c2 45 bc c8 48 ff c1 c4 c2 45 bc c8 48 89 c8 c5 c4 5c f2 48 81 f9 a7 03 00 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}