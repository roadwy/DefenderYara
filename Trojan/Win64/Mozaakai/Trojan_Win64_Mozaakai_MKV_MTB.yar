
rule Trojan_Win64_Mozaakai_MKV_MTB{
	meta:
		description = "Trojan:Win64/Mozaakai.MKV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 c8 8b c1 b9 01 00 00 00 48 6b c9 00 48 8b 54 24 40 0f b6 0c 0a 8b 54 24 20 2b d1 8b ca 48 63 c9 48 8b 54 24 ?? 88 04 0a e9 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}