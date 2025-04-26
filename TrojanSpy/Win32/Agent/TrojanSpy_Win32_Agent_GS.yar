
rule TrojanSpy_Win32_Agent_GS{
	meta:
		description = "TrojanSpy:Win32/Agent.GS,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {57 6a 01 5f 68 e8 03 00 00 8d 85 90 90 fa ff ff 50 53 c7 45 bc 44 00 00 00 89 5d c0 89 5d c8 89 5d cc 89 5d d0 89 5d d4 89 5d d8 89 5d dc 89 5d e0 89 5d e4 89 7d e8 66 89 5d ee 89 5d f0 89 5d f4 89 5d f8 89 5d fc 66 c7 45 ec 05 00 89 5d c4 ff 15 ?? ?? ?? 00 6a 10 e8 ?? 42 00 00 59 8b f0 56 8d 45 bc 50 53 53 6a 20 57 53 53 53 8d 85 90 90 fa ff ff 50 ff 15 ?? ?? ?? 00 85 c0 74 0f ff 36 8b 3d ?? ?? ?? 00 ff d7 ff 76 04 ff d7 } //1
		$a_02_1 = {e8 05 00 00 00 e9 10 00 00 00 68 90 90 80 40 00 b9 ?? 8c 40 00 e8 ?? ?? 00 00 c3 68 62 16 40 00 e8 ?? ?? 00 00 59 c3 b9 ?? 8c 40 00 e9 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}