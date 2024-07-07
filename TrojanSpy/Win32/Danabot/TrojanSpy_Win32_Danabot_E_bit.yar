
rule TrojanSpy_Win32_Danabot_E_bit{
	meta:
		description = "TrojanSpy:Win32/Danabot.E!bit,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {8b e8 8d b5 90 01 04 4e 83 c6 04 81 e6 00 00 ff ff 6a 04 68 00 10 10 00 56 6a 00 e8 90 01 04 8b d8 85 db 90 00 } //1
		$a_03_1 = {51 56 57 8b 75 90 01 01 8b 7d 90 01 01 8b 4d 90 01 01 f3 a4 5f 5e 59 90 00 } //1
		$a_03_2 = {50 8b 45 fc 50 6a 00 6a ff 6a 00 8b 45 90 01 01 50 ff 15 90 00 } //1
		$a_03_3 = {89 47 04 89 18 c6 05 74 90 01 04 83 c3 10 8b c3 90 09 11 00 a1 90 01 04 c7 07 90 01 04 89 1d 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}