
rule Trojan_Win64_Lazy_AB_MTB{
	meta:
		description = "Trojan:Win64/Lazy.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {c0 a8 e2 76 09 00 46 04 15 1f e4 10 b4 dd 01 82 3a 52 eb 20 14 ef d8 be 2c 0e 8d 42 5c 0f a0 dc fa 80 c9 4f } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}