
rule Trojan_Win32_Ursnif_SR_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.SR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {8a d0 81 ff d0 eb 6c 2d 75 90 0a 19 00 a0 90 01 04 8b 75 00 2a c2 02 05 90 00 } //01 00 
		$a_02_1 = {81 c6 ac 43 d5 01 0f b6 ca 81 c1 8a 1d 00 00 0f b7 c3 89 75 00 03 c1 8b 0d 90 01 04 83 c5 04 ff 4c 24 14 0f 85 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Ursnif_SR_MTB_2{
	meta:
		description = "Trojan:Win32/Ursnif.SR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b c3 8b f2 c1 e0 02 2b f0 2b f7 81 ee 49 0d 00 00 89 35 } //01 00 
		$a_03_1 = {8b 8c 28 c7 e8 ff ff 0f b7 05 90 01 04 3b c7 76 0e a1 90 01 04 0f af c6 66 a3 90 01 04 8d 04 13 81 c1 60 e7 ae 01 03 f0 89 0d 90 01 04 a1 d4 33 44 00 89 35 90 01 04 89 8c 28 c7 e8 ff ff 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}