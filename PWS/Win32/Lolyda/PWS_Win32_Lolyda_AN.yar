
rule PWS_Win32_Lolyda_AN{
	meta:
		description = "PWS:Win32/Lolyda.AN,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {8a 04 33 55 04 ?? 34 ?? 2c ?? 47 88 06 46 ff 15 ?? ?? ?? ?? 3b f8 7c e8 } //1
		$a_03_1 = {2b de c6 06 e9 [0-02] 8d 83 ?? ?? ?? ?? [0-01] 8b c8 8b d0 c1 e9 08 88 46 01 88 4e 02 } //2
		$a_03_2 = {68 d0 07 00 00 ff 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 85 c0 74 ec a0 ?? ?? ?? ?? 84 c0 74 e3 e8 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*2+(#a_03_2  & 1)*1) >=3
 
}