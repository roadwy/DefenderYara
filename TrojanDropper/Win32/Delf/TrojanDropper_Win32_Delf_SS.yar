
rule TrojanDropper_Win32_Delf_SS{
	meta:
		description = "TrojanDropper:Win32/Delf.SS,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {ba fc ff ff ff 66 b9 02 00 a1 90 01 04 8b 18 ff 53 08 ba 90 01 04 b9 04 00 00 00 a1 90 01 04 e8 90 01 02 ff ff 8d 95 90 01 02 ff ff b8 90 01 04 e8 90 01 02 ff ff 83 3d 90 01 04 00 75 90 14 8d 95 90 01 02 ff ff b8 90 01 04 e8 90 01 02 ff ff 33 c9 8b 15 90 01 04 a1 90 01 04 8b 18 ff 53 08 8d 95 90 01 02 ff ff b8 90 01 04 e8 90 01 02 ff ff e9 90 16 a1 90 01 04 e8 90 01 02 ff ff 8b d8 a1 90 01 04 e8 90 01 02 ff ff 83 e8 04 3b d8 0f 85 90 00 } //01 00 
		$a_03_1 = {66 b9 02 00 ba fc ff ff ff a1 90 01 04 8b 18 ff 53 08 ba 90 01 04 b9 04 00 00 00 a1 90 01 04 e8 90 01 02 ff ff 8d 95 90 01 02 ff ff b8 90 01 04 e8 90 01 02 ff ff 83 3d 90 01 04 00 75 90 14 8d 95 90 01 02 ff ff b8 90 01 04 e8 90 01 02 ff ff 33 c9 8b 15 90 01 04 a1 90 01 04 8b 18 ff 53 08 8d 95 90 01 02 ff ff b8 90 01 04 e8 90 01 02 ff ff e9 90 16 a1 90 01 04 e8 90 01 02 ff ff 8b d8 a1 90 01 04 e8 90 01 02 ff ff 83 e8 04 3b d8 0f 85 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}