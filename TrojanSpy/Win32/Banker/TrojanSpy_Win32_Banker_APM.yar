
rule TrojanSpy_Win32_Banker_APM{
	meta:
		description = "TrojanSpy:Win32/Banker.APM,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {68 40 1f 00 00 e8 90 01 04 b8 90 01 04 ba 90 01 04 e8 90 01 04 8d 95 18 ff ff ff a1 90 01 04 e8 90 01 04 8b 85 18 ff ff ff e8 90 01 04 50 6a 00 e8 90 01 04 85 c0 76 23 90 00 } //1
		$a_03_1 = {be 0f 00 00 00 8d 8d 30 ff ff ff 8b d6 8b c3 8b 38 ff 57 0c 8b 85 30 ff ff ff 8d 95 34 ff ff ff e8 90 01 04 8b 85 34 ff ff ff 8d 95 38 ff ff ff e8 90 01 04 8b 95 38 ff ff ff a1 90 01 04 8b 08 ff 51 38 46 81 fe 0f 01 00 00 75 b6 90 00 } //1
		$a_03_2 = {68 58 1b 00 00 e8 90 01 04 b8 90 01 04 ba 90 01 04 e8 90 01 04 e9 d4 fe ff ff 33 c0 5a 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}