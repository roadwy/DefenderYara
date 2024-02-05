
rule Trojan_Win32_Ursnif_BA_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.BA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {03 c1 0f b7 15 90 01 04 2b d0 66 89 15 90 01 04 a1 90 01 04 83 e8 2e 8b c8 33 f6 2b 0d 90 01 04 1b 35 90 01 04 0f b7 05 90 01 04 99 03 c1 13 d6 66 a3 90 01 04 e9 90 01 02 ff ff 90 00 } //01 00 
		$a_02_1 = {8b 44 24 08 8b 4c 24 10 0b c8 8b 4c 24 0c 75 90 01 01 8b 44 24 04 f7 e1 c2 90 01 02 53 f7 e1 8b d8 8b 44 24 08 f7 64 24 14 03 d8 8b 44 24 08 f7 e1 03 d3 5b c2 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}