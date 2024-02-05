
rule Trojan_Win32_Ursnif_PVS_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.PVS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 02 00 "
		
	strings :
		$a_02_0 = {6b c0 03 8b d1 2b d0 66 89 15 90 01 04 8b 44 24 14 83 44 24 14 04 81 c6 08 6d 84 01 89 30 90 09 05 00 a1 90 00 } //02 00 
		$a_00_1 = {8d 7c 3f fd 81 c5 dc a3 ed 01 8d 1c b9 8b 7c 24 10 89 2f 81 3d } //02 00 
		$a_02_2 = {8a c1 04 2a 00 05 90 01 04 81 c7 68 e6 32 01 89 7d 00 0f b6 15 90 01 04 8d 41 42 3b d1 77 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}