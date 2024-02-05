
rule TrojanDropper_Win32_Gemeindru_gen_A{
	meta:
		description = "TrojanDropper:Win32/Gemeindru.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {2d e7 03 00 00 0f 80 90 01 01 06 00 00 50 ff 75 90 01 01 68 e8 03 00 00 e8 90 01 02 ff ff 53 e8 90 01 02 ff ff e8 90 01 02 00 00 8b d0 8d 4d 90 01 01 e8 90 01 02 ff ff 50 68 90 01 04 e8 90 01 02 ff ff 8b d0 8d 4d 90 01 01 e8 90 01 02 ff ff 8d 4d 90 01 01 e8 90 01 02 ff ff c7 85 90 01 01 ff ff ff 90 01 04 c7 85 90 01 01 ff ff ff 08 00 00 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}