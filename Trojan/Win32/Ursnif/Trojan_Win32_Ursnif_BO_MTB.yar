
rule Trojan_Win32_Ursnif_BO_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.BO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b 0e 8b d5 2b d0 03 15 90 01 04 8b c3 8d bc 12 90 01 04 0f b7 d7 2b c2 81 c1 90 01 04 83 e8 90 01 01 89 0e 99 83 c6 04 ff 4c 24 10 66 89 3d 90 01 04 89 15 90 01 04 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Ursnif_BO_MTB_2{
	meta:
		description = "Trojan:Win32/Ursnif.BO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {0f af d1 8d 84 38 1c 04 ff ff 8b c8 6b c9 0b 03 d6 2b cf a3 90 01 04 89 15 90 01 04 03 f1 8b 0d 90 01 04 8b de c1 e3 04 2b 5c 24 10 03 cb 83 7c 24 10 06 90 00 } //01 00 
		$a_81_1 = {53 74 75 64 79 6f 62 73 65 72 76 65 2e 70 64 62 } //00 00 
	condition:
		any of ($a_*)
 
}