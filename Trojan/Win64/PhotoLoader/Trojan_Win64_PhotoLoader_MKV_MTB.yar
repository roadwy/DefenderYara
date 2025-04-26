
rule Trojan_Win64_PhotoLoader_MKV_MTB{
	meta:
		description = "Trojan:Win64/PhotoLoader.MKV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {41 0f b6 d3 44 8d 42 01 83 e2 03 41 83 ?? 03 42 8a 44 85 ?? 02 44 95 e0 41 32 04 33 42 8b 4c 85 ?? 41 88 04 1b 83 e1 07 8b 44 95 ?? 49 ff c3 d3 c8 ff c0 89 44 95 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}