
rule Trojan_Win64_ValleyRAT_ARA_MTB{
	meta:
		description = "Trojan:Win64/ValleyRAT.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {42 0f b6 84 22 90 af 01 00 30 04 31 48 ff c1 eb da } //2
		$a_01_1 = {48 8b c1 83 e0 0f 42 02 94 20 60 1a 00 00 80 f2 aa 80 ea 55 88 94 0c 20 06 00 00 48 ff c1 eb c1 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}