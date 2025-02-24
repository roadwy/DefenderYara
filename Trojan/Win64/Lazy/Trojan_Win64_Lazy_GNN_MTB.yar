
rule Trojan_Win64_Lazy_GNN_MTB{
	meta:
		description = "Trojan:Win64/Lazy.GNN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {43 8d 0c 00 44 8b c9 41 81 f1 b7 0d c1 04 45 85 c0 44 0f 49 c9 43 8d 14 09 8b ca 81 f1 b7 0d c1 04 45 85 c9 0f 49 ca ff c3 89 4f fc } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}