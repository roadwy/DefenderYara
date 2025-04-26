
rule Trojan_Win64_BruteRatel_MUV_MTB{
	meta:
		description = "Trojan:Win64/BruteRatel.MUV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {49 c7 c2 1b 00 00 00 49 c7 c4 31 a9 0f 00 4c 03 65 ?? 48 31 d2 41 f7 f2 45 8a 1c 14 44 30 1c 0f 48 ff c1 48 89 c8 48 81 f9 9d d3 03 00 76 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}