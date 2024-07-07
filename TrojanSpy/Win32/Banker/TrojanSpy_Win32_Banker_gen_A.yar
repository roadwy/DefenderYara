
rule TrojanSpy_Win32_Banker_gen_A{
	meta:
		description = "TrojanSpy:Win32/Banker.gen!A,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {8d 55 ec b8 b8 2f 41 00 e8 c2 fa ff ff 8b 45 ec e8 72 11 ff ff 50 6a 00 6a 00 e8 c4 2a ff ff e8 5f 2b ff ff 85 c0 0f 85 f4 02 00 00 be 01 00 00 00 8d 45 e4 e8 ca fb ff ff ff 75 e4 68 c8 2f 41 00 8d 55 e0 b8 d4 2f 41 00 e8 81 fa ff ff ff 75 e0 8d 45 e8 ba 03 00 00 00 e8 e9 0f ff ff 8b 45 e8 e8 09 43 ff ff } //5
		$a_01_1 = {7e 29 bb 01 00 00 00 8d 45 f4 8b 55 fc 0f b6 54 1a ff 2b d3 83 ea 0f e8 b5 13 ff ff 8b 55 f4 8d 45 f8 e8 66 14 ff ff 43 4e 75 dc 8b c7 8b 55 f8 e8 08 12 ff ff 33 c0 5a 59 59 64 89 10 68 ba 27 41 00 8d 45 f4 ba 03 00 00 00 e8 be 11 ff ff c3 } //5
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}