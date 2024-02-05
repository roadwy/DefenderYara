
rule TrojanSpy_Win32_Banker_UUD{
	meta:
		description = "TrojanSpy:Win32/Banker.UUD,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {63 6d 72 73 73 2e 65 78 65 } //01 00 
		$a_00_1 = {5b 62 62 2e 63 6f 6d 2e 62 72 5d } //05 00 
		$a_02_2 = {8d 40 00 55 8b ec 81 c4 04 f0 ff ff 50 83 c4 fc 53 33 c9 89 4d fc 8b d8 33 c0 55 68 90 01 04 64 ff 30 64 89 20 8b c3 e8 90 01 02 ff ff e8 90 01 02 fb ff 8d 95 fc ef ff ff 52 68 ff 0f 00 00 6a 0d 50 e8 90 01 02 fb ff 8d 55 fc 8d 85 fc ef ff ff e8 90 01 02 fb ff ba 90 01 04 8b 45 fc e8 90 01 02 fd ff 84 c0 74 0d b2 01 8b 83 00 03 00 00 e8 90 01 02 fd ff 33 c0 5a 59 59 64 89 10 90 00 } //05 00 
		$a_02_3 = {8d 45 fc b9 90 01 04 8b 15 90 01 04 e8 90 01 02 fb ff b9 90 01 04 b2 01 a1 8c d0 44 00 e8 90 01 02 ff ff 8b d8 ba 02 00 00 80 8b c3 e8 90 01 02 ff ff 33 c9 ba 90 01 04 8b c3 e8 90 01 02 ff ff 8b 45 fc 50 b9 90 01 04 ba 90 01 04 8b c3 e8 90 01 02 ff ff 33 c0 5a 59 59 64 89 10 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}