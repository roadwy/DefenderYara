
rule Trojan_Win64_Sliver_ASV_MTB{
	meta:
		description = "Trojan:Win64/Sliver.ASV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {33 c1 b9 04 00 00 00 48 6b c9 00 48 8b 54 24 40 89 44 0a 1c 48 8b 44 24 40 48 63 40 4c 48 8b 4c 24 40 48 8b 49 78 0f b6 54 24 64 88 14 01 48 8b 44 24 40 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}