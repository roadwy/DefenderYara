
rule Trojan_Win64_Midie_GNK_MTB{
	meta:
		description = "Trojan:Win64/Midie.GNK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 63 c0 48 c1 f2 b2 42 80 b4 44 ?? ?? ?? ?? ?? 42 ff 4c 04 ?? 48 13 e8 5e 4e 8b 94 83 ?? ?? ?? ?? ff ce 36 66 43 8b 34 8a 48 8d 8a ?? ?? ?? ?? 0f 8d } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}