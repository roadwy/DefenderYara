
rule Trojan_Win32_Midie_MKV_MTB{
	meta:
		description = "Trojan:Win32/Midie.MKV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {2b c2 66 8b 44 24 c6 66 83 c1 4c 03 7d f0 88 17 66 33 d0 8b d1 66 8b 44 24 ?? 80 c1 0c 80 e9 15 34 1e 30 1f 66 83 e8 10 66 03 ca 03 c1 66 03 44 24 a0 66 8b c8 8b 7d fc } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}