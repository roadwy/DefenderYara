
rule TrojanSpy_Win32_Banker_VCM{
	meta:
		description = "TrojanSpy:Win32/Banker.VCM,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 "
		
	strings :
		$a_03_0 = {e9 96 00 00 00 81 fb 02 00 00 80 75 3e 8d 55 ec b8 90 01 03 00 e8 90 01 02 ff ff 8b 55 ec 8d 45 f0 e8 90 01 02 ff ff 90 00 } //10
		$a_01_1 = {0f b6 44 38 ff 89 45 e8 47 8b 75 f8 85 f6 74 05 83 ee 04 8b 36 3b f7 7d 05 } //1
		$a_01_2 = {0f b6 5c 38 ff 33 5d e4 3b 5d e8 7f 0b 81 c3 ff 00 00 00 2b 5d e8 eb 03 } //1
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=11
 
}