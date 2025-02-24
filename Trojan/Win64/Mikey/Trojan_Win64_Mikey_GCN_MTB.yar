
rule Trojan_Win64_Mikey_GCN_MTB{
	meta:
		description = "Trojan:Win64/Mikey.GCN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {03 d0 0f be c2 6b d0 ?? 0f b6 c1 02 c0 ff c1 41 2a d0 80 c2 ?? 02 d0 41 30 51 ?? 83 f9 } //10
		$a_01_1 = {9f a4 2b d7 7d 27 2e d6 9f a4 2f d7 5a 27 2e d6 17 5f 2f d7 55 27 2e d6 5c 27 2f d6 a5 27 2e d6 4f a3 27 d7 5d 27 2e d6 4f a3 d1 d6 5d 27 2e d6 4f a3 } //10
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*10) >=10
 
}