
rule Trojan_Win64_PondRAT_MKV_MTB{
	meta:
		description = "Trojan:Win64/PondRAT.MKV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 8b c3 48 8d 52 01 83 e0 1f 48 ff c3 0f b6 44 05 ?? 30 42 ff 49 83 e8 01 75 } //4
		$a_03_1 = {8b d6 44 8b c3 48 8b c2 48 8d 49 01 83 e0 1f 48 ff c2 0f b6 44 05 ?? 30 41 ff 49 83 e8 01 75 } //5
	condition:
		((#a_03_0  & 1)*4+(#a_03_1  & 1)*5) >=9
 
}