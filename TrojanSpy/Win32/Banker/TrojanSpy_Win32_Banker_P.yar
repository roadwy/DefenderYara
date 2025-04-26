
rule TrojanSpy_Win32_Banker_P{
	meta:
		description = "TrojanSpy:Win32/Banker.P,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_03_0 = {40 89 c7 8d b3 ?? ?? ?? ?? 8b c3 b9 26 00 00 00 99 f7 f9 8b 45 ?? 8a 14 10 32 16 } //4
		$a_03_1 = {8a 18 80 f3 ?? 88 1a 42 40 49 75 f4 } //3
		$a_01_2 = {2c 5b 5f 10 00 15 14 0c 40 02 58 35 } //1 嬬ၟᔀఔɀ㕘
		$a_01_3 = {06 1a 01 0c 03 53 3e 3a 55 22 17 11 1c 1b 05 0a } //1 ᨆఁ匃㨾≕ᄗᬜਅ
	condition:
		((#a_03_0  & 1)*4+(#a_03_1  & 1)*3+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}