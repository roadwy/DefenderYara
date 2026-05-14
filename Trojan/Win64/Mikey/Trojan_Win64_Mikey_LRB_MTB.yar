
rule Trojan_Win64_Mikey_LRB_MTB{
	meta:
		description = "Trojan:Win64/Mikey.LRB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_01_0 = {41 8d 49 0c c0 e1 03 41 0f b6 02 33 c8 88 0a 66 45 03 cb 66 44 89 4c 24 38 4d 03 d3 4c 89 14 24 49 03 d3 48 89 54 24 08 } //10
		$a_03_1 = {0f b6 c1 4c 33 c8 42 8d 04 11 41 02 c0 24 3f a8 df 74 ?? 49 8b d1 0f b6 c8 48 d3 c2 4c 33 ca 49 ff c0 41 8a 08 84 c9 } //20
	condition:
		((#a_01_0  & 1)*10+(#a_03_1  & 1)*20) >=30
 
}