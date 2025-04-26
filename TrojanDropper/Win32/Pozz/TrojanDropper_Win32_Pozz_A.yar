
rule TrojanDropper_Win32_Pozz_A{
	meta:
		description = "TrojanDropper:Win32/Pozz.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {68 75 8b 00 00 e8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 5a 8d 94 02 87 e6 0b 00 } //1
		$a_03_1 = {b9 8b 39 5b 00 b8 ?? ?? 54 00 81 c7 80 00 00 00 f3 ab 8b 8a 98 a4 c7 00 } //1
		$a_03_2 = {50 50 6a 03 50 50 68 c9 cb 08 c0 81 2c 24 c9 cb 08 00 68 ?? ?? ?? ?? e8 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}