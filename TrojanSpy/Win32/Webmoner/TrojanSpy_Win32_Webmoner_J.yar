
rule TrojanSpy_Win32_Webmoner_J{
	meta:
		description = "TrojanSpy:Win32/Webmoner.J,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {31 35 32 25 37 76 2e 51 30 46 2e 33 30 79 2e 2a 31 37 } //1 152%7v.Q0F.30y.*17
		$a_01_1 = {74 74 74 74 74 74 74 74 74 74 74 74 74 74 74 74 74 20 64 66 73 64 66 73 64 66 20 75 69 68 69 75 61 74 74 74 74 74 74 74 74 74 74 74 74 74 74 74 74 74 74 74 68 } //1 ttttttttttttttttt dfsdfsdf uihiuattttttttttttttttttth
		$a_02_2 = {5c 26 73 23 79 32 73 57 74 37 65 2a 6d 6d 33 2f 32 77 5c 57 64 63 72 2a 69 23 76 51 65 32 72 35 73 77 5c 46 65 77 74 38 63 37 5c 26 68 2a 6f 35 73 23 74 37 73 26 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 5c 62 73 37 76 32 63 37 68 79 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_02_2  & 1)*1) >=3
 
}