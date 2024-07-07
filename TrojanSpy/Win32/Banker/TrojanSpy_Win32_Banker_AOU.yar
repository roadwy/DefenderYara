
rule TrojanSpy_Win32_Banker_AOU{
	meta:
		description = "TrojanSpy:Win32/Banker.AOU,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8d 85 54 f0 ff ff 50 b9 90 01 04 ba 90 01 04 8b 45 fc e8 90 01 04 8b 85 54 f0 ff ff 50 8d 85 4c f0 ff ff 8d 95 5a f0 ff ff b9 d1 07 00 00 e8 90 01 04 8b 85 4c f0 ff ff 8d 95 50 f0 ff ff e8 90 01 04 8b 95 50 f0 ff ff b9 01 00 00 00 58 e8 90 01 04 85 c0 0f 8f c6 00 00 00 68 90 01 04 8d 85 48 f0 ff ff 50 b9 90 01 04 ba 90 01 04 8b 45 fc 90 00 } //1
		$a_03_1 = {b9 01 00 00 00 58 e8 90 01 04 85 c0 7f 65 68 90 01 04 8d 85 90 01 04 50 b9 90 01 04 ba 90 01 04 8b 45 fc e8 90 01 04 8b 85 90 01 04 50 8d 85 90 01 04 8d 95 5a f0 ff ff b9 d1 07 00 00 e8 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}