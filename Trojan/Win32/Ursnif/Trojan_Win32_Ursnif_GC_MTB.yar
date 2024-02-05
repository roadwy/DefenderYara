
rule Trojan_Win32_Ursnif_GC_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.GC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b 02 8b 4d 90 01 01 8d 54 01 90 01 01 8b 45 90 01 01 89 10 8b 4d 90 01 01 8b 11 83 ea 90 01 01 8b 45 90 01 01 89 10 8b e5 90 00 } //01 00 
		$a_02_1 = {8b ff c7 05 90 02 30 01 05 90 02 20 8b ff 8b 0d 90 02 20 8b 15 90 02 20 89 11 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Ursnif_GC_MTB_2{
	meta:
		description = "Trojan:Win32/Ursnif.GC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_02_0 = {0f b6 c8 83 c1 90 01 01 03 cf 89 0d 90 02 04 90 18 8b 7c 24 90 01 01 81 c3 90 02 04 0f b6 c8 66 2b ca 89 1d 90 02 04 89 1f 83 c7 90 01 01 8b 1d 90 02 04 66 03 cb 66 03 4c 24 90 01 01 66 03 f1 89 7c 24 90 01 01 ff 4c 24 90 01 01 8b 7c 24 90 01 01 66 89 74 24 90 01 01 0f 85 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}