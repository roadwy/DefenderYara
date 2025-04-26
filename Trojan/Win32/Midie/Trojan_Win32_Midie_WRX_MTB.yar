
rule Trojan_Win32_Midie_WRX_MTB{
	meta:
		description = "Trojan:Win32/Midie.WRX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {34 1e 30 1f 66 83 e8 10 66 03 ca 03 c1 66 03 44 24 ?? 66 8b c8 8b 7d fc 47 89 7d fc 8a 44 24 cc 66 33 4c 24 d4 b0 28 2a 4c 24 e0 03 4c 24 f5 83 6d f8 01 0f 85 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}