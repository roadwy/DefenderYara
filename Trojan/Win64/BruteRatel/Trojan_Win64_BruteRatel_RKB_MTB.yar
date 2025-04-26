
rule Trojan_Win64_BruteRatel_RKB_MTB{
	meta:
		description = "Trojan:Win64/BruteRatel.RKB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {4d 63 c2 48 b8 93 24 49 92 24 49 92 24 45 03 d4 49 8b c8 49 f7 e0 48 2b ca 48 d1 e9 48 03 ca 48 c1 e9 04 48 6b c1 1c 4c 2b c0 42 8a 44 04 20 42 32 04 1b 41 88 03 4d 03 dc 41 81 fa 00 8c 04 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}