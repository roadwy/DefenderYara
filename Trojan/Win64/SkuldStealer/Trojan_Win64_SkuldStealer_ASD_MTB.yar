
rule Trojan_Win64_SkuldStealer_ASD_MTB{
	meta:
		description = "Trojan:Win64/SkuldStealer.ASD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {c0 ea 04 83 e7 0f c1 e7 04 09 d7 40 88 3c 31 48 ff c6 44 89 c2 48 39 f3 7e 21 89 d7 c1 e2 02 41 89 f8 40 c0 ef 03 09 d7 0f b6 14 30 31 fa 29 f2 0f 1f 40 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}