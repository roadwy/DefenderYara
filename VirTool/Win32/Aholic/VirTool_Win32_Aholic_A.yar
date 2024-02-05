
rule VirTool_Win32_Aholic_A{
	meta:
		description = "VirTool:Win32/Aholic.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_02_0 = {53 6a 32 68 90 01 04 ff d6 ff b5 90 01 02 ff ff 53 6a 04 68 90 01 04 ff d6 ff b5 90 01 02 ff ff 53 6a 04 68 90 01 04 ff d6 ff 35 90 01 04 8d 45 e8 68 90 01 04 50 ff 15 90 01 04 83 c4 48 8d 85 90 01 02 ff ff 50 68 ff 00 00 00 90 00 } //01 00 
		$a_02_1 = {53 68 b6 01 00 00 6a 02 8d 85 90 01 02 ff ff 50 8d 8d 90 01 02 ff ff ff 15 90 01 04 8d 8d 90 01 02 ff ff 88 5d fc ff 15 90 01 04 8d 85 90 01 02 ff ff 68 90 01 04 50 ff 15 90 01 04 03 3d 90 01 04 6a 02 f7 df 57 90 00 } //01 00 
		$a_02_2 = {c2 04 00 6a 74 68 90 01 04 e8 90 01 02 00 00 33 db 89 5d e0 53 8b 3d 90 01 04 ff d7 66 81 38 4d 5a 75 1f 8b 48 3c 03 c8 81 39 50 45 00 00 75 12 0f b7 41 18 3d 0b 01 00 00 74 1f 3d 0b 02 00 00 74 05 89 5d e4 eb 27 83 b9 84 00 00 00 0e 76 f2 33 c0 39 99 f8 00 00 00 90 00 } //01 00 
		$a_02_3 = {59 53 33 c0 50 50 8d 8d 90 01 02 ff ff 51 68 90 01 04 50 ff 15 90 01 04 83 c7 3a 8b c7 6a 02 f7 d8 50 ff b5 90 01 02 ff ff ff 15 90 01 04 ff b5 90 01 02 ff ff 53 6a 32 68 90 01 04 ff d6 ff b5 90 01 02 ff ff 53 6a 04 68 90 01 04 ff d6 ff b5 90 01 02 ff ff 53 6a 04 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}