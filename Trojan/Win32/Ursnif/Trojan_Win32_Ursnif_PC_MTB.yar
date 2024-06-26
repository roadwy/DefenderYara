
rule Trojan_Win32_Ursnif_PC_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.PC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {f7 d0 88 85 90 01 04 0f b6 8d 90 01 04 2b 8d 90 01 04 88 8d 90 01 04 0f b6 95 90 01 04 f7 da 88 95 90 01 04 0f b6 85 90 01 04 c1 f8 03 0f b6 8d 90 01 04 c1 e1 05 0b c1 88 85 90 01 04 0f b6 95 90 01 04 f7 da 88 95 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Ursnif_PC_MTB_2{
	meta:
		description = "Trojan:Win32/Ursnif.PC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {8d 1c 7f 2b dd c7 44 24 90 01 01 00 00 00 00 8d 0c 40 2b cb 0f b7 c9 bf 2a 00 00 00 2b f9 2b fd 03 c7 8b 3d 90 01 03 00 8b 8c 37 90 01 02 ff ff 81 c1 64 c8 31 01 89 8c 37 90 01 02 ff ff 8d 7c 00 fb 0f b7 ff 89 7c 24 10 0f b7 ff 8d 94 2a 5c b3 fe ff 8b ef 2b ea 83 c6 04 8d 44 28 90 01 01 a3 90 01 03 00 81 fe 90 01 02 00 00 0f 82 90 01 01 ff ff ff 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}