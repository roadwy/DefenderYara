
rule Trojan_Win64_CRat_MA_MTB{
	meta:
		description = "Trojan:Win64/CRat.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {4b 8d 04 02 48 99 83 e2 07 48 03 c2 48 8b c8 83 e0 07 48 2b c2 48 c1 f9 03 48 63 c9 0f b6 14 29 8b c8 b8 01 00 00 00 d3 e0 84 d0 74 ?? 41 b9 ff 00 00 00 45 2a 08 45 88 08 49 ff c0 4c 3b c3 72 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}