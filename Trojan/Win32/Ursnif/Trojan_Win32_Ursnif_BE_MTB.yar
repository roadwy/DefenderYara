
rule Trojan_Win32_Ursnif_BE_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.BE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_02_0 = {2b c2 0f b7 0d 90 01 04 2b c8 66 89 0d 90 01 04 8b 15 90 01 04 81 c2 90 01 04 89 15 90 01 04 a1 90 01 04 03 45 90 01 01 8b 0d 90 01 04 89 88 90 01 04 0f b7 15 90 01 04 0f b6 05 90 01 04 2b d0 0f b7 0d 90 01 04 03 d1 90 00 } //01 00 
		$a_02_1 = {03 ca 88 0d 90 01 04 e9 90 00 } //00 00 
		$a_00_2 = {78 74 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Ursnif_BE_MTB_2{
	meta:
		description = "Trojan:Win32/Ursnif.BE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {0f b7 c0 2b f0 8d 47 b5 83 c6 4a 0f af 35 90 01 04 2b f1 0f b7 c9 03 c1 0f b7 c0 83 c0 07 03 c6 8d 7e 51 69 d0 89 1c 00 00 8d 81 04 d0 ff ff 2b d6 03 c2 0f b7 c8 0f af ca 8d 04 32 03 c0 2b cf 2b c1 05 5c 96 ff ff 05 cc cb ff ff 03 c2 8d 34 47 0f b6 05 90 01 04 03 f1 0f b7 d6 81 ea 55 70 00 00 0f b7 de 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}