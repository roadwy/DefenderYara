
rule Trojan_Win64_Mockbit_AA_MTB{
	meta:
		description = "Trojan:Win64/Mockbit.AA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {81 e1 ff 00 00 00 0f b6 c9 03 c1 0f b7 4c 24 ?? 48 8b 54 24 ?? 88 04 0a 0f b6 44 24 ?? 0f b6 4c 24 ?? 33 c1 0f b7 4c 24 ?? 48 8b 54 24 ?? 88 04 0a 90 13 0f b7 44 24 ?? 66 ff c0 66 89 44 24 ?? 0f b7 44 24 ?? 0f b7 4c 24 ?? 3b c1 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}