
rule Trojan_Win64_IcedID_NEAB_MTB{
	meta:
		description = "Trojan:Win64/IcedID.NEAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 44 24 44 ff c0 89 44 24 44 8b 84 24 98 00 00 00 39 44 24 44 73 48 48 63 44 24 44 48 8b 4c 24 58 0f b6 04 01 89 44 24 68 48 63 4c 24 44 33 d2 48 8b c1 b9 08 00 00 00 48 f7 f1 48 8b c2 48 8b 4c 24 48 0f b6 44 01 10 8b 4c 24 68 33 c8 8b c1 48 63 4c 24 44 48 8b 54 24 58 88 04 0a eb a1 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}