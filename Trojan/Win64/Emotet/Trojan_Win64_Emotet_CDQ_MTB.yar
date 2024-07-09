
rule Trojan_Win64_Emotet_CDQ_MTB{
	meta:
		description = "Trojan:Win64/Emotet.CDQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {4d 8d 40 01 f7 eb 8b cb [0-04] ff c3 c1 fa ?? 8b c2 c1 e8 ?? 03 d0 6b c2 ?? 2b c8 48 8b 44 24 40 48 63 d1 0f b6 8c 32 00 b2 04 00 41 32 4c 00 ff 48 8b 44 24 38 41 88 4c 00 ff 48 63 c3 48 3b 44 24 30 72 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}