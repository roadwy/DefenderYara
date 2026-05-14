
rule Trojan_Win64_Midie_SXH_MTB{
	meta:
		description = "Trojan:Win64/Midie.SXH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,32 00 32 00 02 00 00 "
		
	strings :
		$a_01_0 = {0f b6 04 17 48 ff c2 03 c3 8d 0c c0 8b d9 c1 eb 06 33 d9 49 3b d0 75 e8 } //30
		$a_03_1 = {49 8b c0 83 e0 0f 0f b6 0c 08 49 03 c9 48 03 ca 44 0f b6 c9 42 8a 44 0c ?? 42 88 44 04 ?? 4c 03 c3 42 88 54 0c ?? 4c 3b c5 72 c8 } //20
	condition:
		((#a_01_0  & 1)*30+(#a_03_1  & 1)*20) >=50
 
}