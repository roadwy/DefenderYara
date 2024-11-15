
rule Trojan_Win64_BruteRatel_MKV_MTB{
	meta:
		description = "Trojan:Win64/BruteRatel.MKV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {45 03 d4 48 f7 e1 48 c1 ea 04 48 8d 04 52 48 c1 e0 ?? 48 2b c8 48 03 cb 8a 44 0c ?? 42 32 04 1f 41 88 03 4d 03 dc 41 81 fa 00 2c 04 00 72 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}