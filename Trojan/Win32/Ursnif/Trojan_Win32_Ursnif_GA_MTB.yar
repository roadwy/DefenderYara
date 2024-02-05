
rule Trojan_Win32_Ursnif_GA_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b 4d 74 30 04 31 b8 90 01 04 83 f0 90 01 01 83 6d 90 02 10 83 7d 90 02 10 0f 8d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Ursnif_GA_MTB_2{
	meta:
		description = "Trojan:Win32/Ursnif.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_02_0 = {0f b6 f0 2b de 8b 37 03 eb b3 59 f6 eb 8a da 2a d8 81 3d 90 02 08 88 1d 90 02 04 90 18 8b 1d 90 02 04 81 c6 90 02 04 8a ca 2a cb 89 37 80 c1 90 01 01 83 c7 90 01 01 83 6c 24 90 01 01 01 89 35 90 02 04 0f 85 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}