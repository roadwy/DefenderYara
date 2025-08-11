
rule Trojan_Win64_Latrodectus_BH_MTB{
	meta:
		description = "Trojan:Win64/Latrodectus.BH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {c5 dd 69 e9 c5 dd 61 e1 0f 58 c8 0f 28 c3 90 90 90 49 21 c4 49 83 eb 0a 90 41 88 0c 08 90 90 90 48 ff c1 41 08 ce 48 83 f9 72 } //4
		$a_01_1 = {c5 d5 fd f5 4c 8d 44 24 20 c5 fd 67 c0 c5 f5 67 c9 } //1
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}