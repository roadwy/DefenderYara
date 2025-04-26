
rule Trojan_Win32_Trickbot_V_ibt{
	meta:
		description = "Trojan:Win32/Trickbot.V!ibt,SIGNATURE_TYPE_PEHSTR,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {6a 00 6a 62 c7 01 63 00 00 00 e8 67 09 ff ff 6a 01 6a 72 88 41 04 e8 5b 09 ff ff 6a 02 6a 6f 88 41 05 e8 4f 09 ff ff 6a 03 6a 77 88 41 06 e8 43 09 ff ff 6a 04 6a 73 88 41 07 e8 37 09 ff ff 6a 05 6a 65 88 41 08 e8 2b 09 ff ff 6a 06 6a 72 88 41 09 e8 1f 09 ff ff 88 41 0a c6 41 0b 00 8a 41 04 8b c1 c2 04 00 } //1
		$a_01_1 = {56 8b 75 08 83 c9 ff 85 f6 74 18 0f b6 02 33 c1 c1 e9 08 0f b6 c0 33 0c 85 18 6b 04 10 42 83 ee 01 75 e8 f7 d1 8b c1 5e 8b e5 5d c3 } //1
		$a_01_2 = {56 43 32 30 58 43 30 30 55 8b ec 83 ec 08 53 56 57 55 fc ff 75 10 e8 27 de fc ff 83 c4 04 8b 5d 0c 8b 45 08 f7 40 04 06 00 00 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}