
rule Trojan_Win64_Donut_MKV_MTB{
	meta:
		description = "Trojan:Win64/Donut.MKV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 8b c3 83 e0 0f 0f b6 04 08 30 04 1f 48 ff c3 49 3b de 72 ?? 4c 8d 4c 24 48 41 b8 20 00 00 00 49 8b d6 48 8b cf ff 15 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}