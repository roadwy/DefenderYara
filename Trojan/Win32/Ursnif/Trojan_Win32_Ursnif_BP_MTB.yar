
rule Trojan_Win32_Ursnif_BP_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.BP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {6b d2 55 2b d7 66 01 15 90 01 04 8b 44 24 18 81 c6 90 01 04 83 d3 00 0f a4 f3 01 99 03 f6 2b f0 a1 90 01 04 1b da 8b 54 24 10 03 f1 13 dd 05 90 01 04 89 02 0f b7 15 90 01 04 a3 90 01 04 8d 04 36 0f b7 f8 0f b7 05 90 01 04 2b c2 89 44 24 14 3d 90 01 04 75 90 00 } //01 00 
		$a_02_1 = {6b d2 55 2b c2 99 2b f0 1b da 83 44 24 10 04 ff 4c 24 1c 0f 85 90 01 02 ff ff 90 00 } //00 00 
		$a_00_2 = {5d } //04 00  ]
	condition:
		any of ($a_*)
 
}