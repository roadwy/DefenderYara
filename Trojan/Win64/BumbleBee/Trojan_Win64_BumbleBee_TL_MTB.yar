
rule Trojan_Win64_BumbleBee_TL_MTB{
	meta:
		description = "Trojan:Win64/BumbleBee.TL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {49 bd bb bb 54 a7 f8 f7 51 92 49 ba 00 c4 17 00 00 00 00 00 44 30 2e 48 81 c6 01 00 00 00 49 81 c5 1c 77 11 09 49 81 ea 01 00 00 00 0f 85 e2 ff ff ff } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}