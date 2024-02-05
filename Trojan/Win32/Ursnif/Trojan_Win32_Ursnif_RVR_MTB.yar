
rule Trojan_Win32_Ursnif_RVR_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.RVR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b 4c 24 24 8d 42 02 03 c3 81 c7 f8 cb fb 01 0f b7 c0 89 3d 90 01 04 89 39 8d 70 a2 69 c0 41 64 00 00 89 74 24 24 03 05 90 01 04 0f b7 c8 8b 44 24 14 83 c0 04 89 4c 24 10 89 44 24 14 3d 90 01 04 73 90 00 } //01 00 
		$a_02_1 = {0f af da 2b de 8b 4c 24 10 05 34 83 98 01 89 84 0f 9a e1 ff ff bf 90 01 04 83 c1 04 2b fb 89 4c 24 10 81 f9 5e 1f 00 00 0f 82 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}