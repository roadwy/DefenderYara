
rule TrojanSpy_Win32_Banker_UTA{
	meta:
		description = "TrojanSpy:Win32/Banker.UTA,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {55 8b ec 6a 00 6a 00 6a 00 53 56 57 8b fa 89 45 fc 8b 45 fc e8 e7 fb f4 ff 33 c0 55 68 1b 4b 4b 00 64 ff 30 64 89 20 8b 45 fc e8 e1 f9 f4 ff 8b f0 85 f6 7e 29 bb 01 00 00 00 8d 45 f4 8b 55 fc 0f b6 54 1a ff 2b d3 83 ea 0f e8 e9 f8 f4 ff 8b 55 f4 8d 45 f8 e8 be f9 f4 ff 43 4e 75 dc 8b c7 8b 55 f8 e8 3c f7 f4 ff 33 c0 5a 59 59 64 89 10 68 22 4b 4b 00 8d 45 f4 ba 03 00 00 00 e8 f2 f6 f4 ff c3 } //00 00 
	condition:
		any of ($a_*)
 
}