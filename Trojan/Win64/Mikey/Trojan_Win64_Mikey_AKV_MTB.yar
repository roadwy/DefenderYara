
rule Trojan_Win64_Mikey_AKV_MTB{
	meta:
		description = "Trojan:Win64/Mikey.AKV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {4c 8b d2 45 33 c9 4c 2b d1 4c 8b c1 b8 a1 a0 a0 a0 41 f7 e1 c1 ea 05 0f be c2 6b c8 33 41 8a c1 41 ff c1 2a c1 04 32 43 32 04 10 41 88 00 49 ff c0 41 83 f9 0d 7c d5 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}