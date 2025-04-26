
rule TrojanSpy_Win32_Ambler_E{
	meta:
		description = "TrojanSpy:Win32/Ambler.E,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_02_0 = {33 d2 39 51 08 7e 0f 8b 41 04 80 34 10 ?? 03 c2 42 3b [0-02] 7c f1 c3 } //1
		$a_02_1 = {7e 1a 53 56 8b 41 04 6a ?? 5b 8d 34 07 8b c7 99 f7 fb 30 16 47 3b 79 08 7c ea } //1
		$a_02_2 = {ff 75 0c ff d7 59 85 c0 59 75 10 68 ?? ?? ?? ?? ff 75 08 ff d7 59 85 c0 59 74 08 6a 01 58 e9 ?? 01 00 00 8a 45 0b } //2
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*2) >=3
 
}