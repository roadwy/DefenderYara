
rule TrojanSpy_Win32_Banker_AOP{
	meta:
		description = "TrojanSpy:Win32/Banker.AOP,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {3d 00 44 00 4b 00 55 00 50 00 44 00 54 00 3d 00 } //1 =DKUPDT=
		$a_03_1 = {2e 00 63 00 70 00 6c 00 90 02 16 63 00 6d 00 64 00 20 00 2f 00 63 00 90 00 } //1
		$a_03_2 = {83 fb 01 75 0d 8d 55 fc b8 90 01 04 e8 90 01 04 83 fb 02 75 0d 8d 55 fc b8 90 01 04 e8 90 01 04 83 fb 03 75 0d 8d 55 fc b8 90 01 04 e8 90 01 04 33 c0 55 90 00 } //1
		$a_01_3 = {74 05 83 e8 04 8b 00 89 45 ec 33 f6 8d 45 dc 50 b9 02 00 00 00 ba 01 00 00 00 8b 45 fc } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}
rule TrojanSpy_Win32_Banker_AOP_2{
	meta:
		description = "TrojanSpy:Win32/Banker.AOP,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {3d 44 4b 55 50 44 54 3d } //1 =DKUPDT=
		$a_03_1 = {0f 84 2a 01 00 00 8d 95 5c fe ff ff b8 90 01 04 e8 90 01 04 ff b5 5c fe ff ff 68 90 01 04 8d 85 58 fe ff ff 50 ba 08 00 00 00 b8 04 00 00 00 e8 90 01 04 b1 01 33 d2 e8 90 00 } //1
		$a_03_2 = {83 fb 01 75 0d 8d 90 01 02 90 03 01 01 b8 ba 90 01 04 e8 90 01 04 83 fb 02 75 0d 8d 90 01 02 90 03 01 01 b8 ba 90 01 04 e8 90 01 04 83 fb 03 75 0d 8d 90 01 02 90 03 01 01 b8 ba 90 01 04 e8 90 01 04 33 c0 55 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}