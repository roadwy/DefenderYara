
rule TrojanDropper_Win32_Postdru_gen_A{
	meta:
		description = "TrojanDropper:Win32/Postdru.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {bb 00 38 00 00 2b f3 56 8d 45 f4 b9 01 00 00 00 8b 15 90 01 04 e8 90 01 02 ff ff 83 c4 04 8b d3 8d 85 90 01 02 ff ff e8 90 01 02 ff ff e8 90 01 02 ff ff a1 90 01 04 c6 00 02 8b 55 fc 8d 85 90 01 02 ff ff e8 90 01 02 ff ff ba 01 00 00 00 8d 85 90 01 02 ff ff e8 90 01 02 ff ff e8 90 01 02 ff ff 6a 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}