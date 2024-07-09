
rule Trojan_Win64_Emotet_PAD_MTB{
	meta:
		description = "Trojan:Win64/Emotet.PAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b cb f7 eb ff c3 c1 fa ?? 8b c2 c1 e8 ?? 03 d0 6b c2 ?? 2b c8 48 63 c1 42 8a 0c ?? 43 32 0c ?? 41 88 0b 49 ff c3 49 83 ee ?? 74 [0-04] 4c 8b [0-06] eb } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}