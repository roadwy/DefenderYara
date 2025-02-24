
rule Trojan_Win64_Dridex_LZV_MTB{
	meta:
		description = "Trojan:Win64/Dridex.LZV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a 14 01 4c 8b 44 24 08 41 88 14 00 8a 54 24 ?? 80 f2 ff 88 54 24 27 48 83 c0 01 4c 8b 4c 24 28 49 81 e9 8c f8 35 37 4c 89 4c 24 28 66 44 8b 54 24 ?? 66 44 23 54 24 36 66 44 89 54 24 ?? 4c 8b 4c 24 10 4c 39 c8 48 89 04 24 74 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}