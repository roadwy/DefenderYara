
rule Trojan_Win64_Emotet_BG_MTB{
	meta:
		description = "Trojan:Win64/Emotet.BG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {f7 ea c1 fa ?? 89 c8 c1 f8 ?? 29 c2 89 d0 6b c0 ?? 29 c1 89 c8 48 98 4c 01 d0 0f b6 00 44 31 c8 41 88 00 83 85 [0-06] 83 85 [0-06] 8b 85 [0-06] 3b 85 [0-06] 0f 8c } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}