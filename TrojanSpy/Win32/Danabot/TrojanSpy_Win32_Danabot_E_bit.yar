
rule TrojanSpy_Win32_Danabot_E_bit{
	meta:
		description = "TrojanSpy:Win32/Danabot.E!bit,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {8b e8 8d b5 ?? ?? ?? ?? 4e 83 c6 04 81 e6 00 00 ff ff 6a 04 68 00 10 10 00 56 6a 00 e8 ?? ?? ?? ?? 8b d8 85 db } //1
		$a_03_1 = {51 56 57 8b 75 ?? 8b 7d ?? 8b 4d ?? f3 a4 5f 5e 59 } //1
		$a_03_2 = {50 8b 45 fc 50 6a 00 6a ff 6a 00 8b 45 ?? 50 ff 15 } //1
		$a_03_3 = {89 47 04 89 18 c6 05 74 ?? ?? ?? ?? 83 c3 10 8b c3 90 09 11 00 a1 ?? ?? ?? ?? c7 07 ?? ?? ?? ?? 89 1d } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}