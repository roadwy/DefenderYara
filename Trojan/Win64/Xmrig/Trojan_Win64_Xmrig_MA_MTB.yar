
rule Trojan_Win64_Xmrig_MA_MTB{
	meta:
		description = "Trojan:Win64/Xmrig.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {e9 3f 01 00 00 4c 8d 1d e4 ff ff ff eb 03 30 af ba 4c 8d 15 e8 ff ff ff eb 02 1a ab 80 3d 38 04 00 00 00 eb 03 b9 16 9b 4d 0f 45 d3 eb 01 a9 b8 b0 61 17 00 eb 02 4f bc 4d 8b e2 eb 02 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}