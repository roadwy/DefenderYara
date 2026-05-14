
rule Trojan_Win64_NjRat_AB_MTB{
	meta:
		description = "Trojan:Win64/NjRat.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 01 00 00 "
		
	strings :
		$a_01_0 = {57 56 48 83 ec 38 48 8d 35 e3 2c 00 00 31 c0 48 8d 7c 24 0f 49 89 c8 b9 21 00 00 00 f3 a4 48 39 d0 74 13 48 89 c1 83 e1 1f 8a 4c 0c 0f 41 30 0c 00 48 ff c0 eb e8 } //6
	condition:
		((#a_01_0  & 1)*6) >=6
 
}