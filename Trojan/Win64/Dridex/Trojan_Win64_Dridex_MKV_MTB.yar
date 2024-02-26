
rule Trojan_Win64_Dridex_MKV_MTB{
	meta:
		description = "Trojan:Win64/Dridex.MKV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {0f af d2 48 89 8c 24 90 01 04 c1 e2 01 89 54 24 7c 8b 54 24 3c 33 94 24 88 00 00 00 89 94 24 90 01 04 8b 54 24 3c 0f af d2 48 c7 84 24 90 01 04 75 fd a1 ef 89 94 24 84 00 00 00 8b 54 24 5c 44 8b 44 24 3c 45 0f af c0 44 89 44 24 78 39 d0 0f 87 90 00 } //01 00 
		$a_03_1 = {45 89 c8 44 89 c2 44 8b 84 24 90 01 04 41 81 c0 30 88 7e 1f 44 89 84 24 88 00 00 00 8a 0c 10 88 8c 24 90 01 04 44 8b 44 24 4c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}