
rule PWS_Win32_Yaludle_D{
	meta:
		description = "PWS:Win32/Yaludle.D,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {8a 41 01 41 84 c0 75 f4 53 8a 19 33 c0 3a da 0f 95 c0 48 5b 23 c1 c3 } //1
		$a_03_1 = {85 c0 74 16 2d ?? ?? ?? ?? b9 ?? 00 00 00 83 c0 ?? 99 f7 f9 8a 9a ?? ?? ?? ?? 88 1c 2e 8a 46 01 47 46 84 c0 75 c2 } //1
		$a_01_2 = {68 4d a0 07 6c 56 e8 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*2) >=3
 
}
rule PWS_Win32_Yaludle_D_2{
	meta:
		description = "PWS:Win32/Yaludle.D,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {40 eb f1 8a 08 2a 4c 24 08 f6 d9 1b c9 f7 d1 23 c1 } //1
		$a_03_1 = {59 74 13 2b c6 6a ?? 83 c0 ?? 59 99 f7 f9 5e 8a 82 ?? ?? ?? ?? c3 } //1
		$a_03_2 = {74 62 ff 45 f8 83 45 fc 08 39 75 f8 72 e1 8d 85 ?? ?? ?? ?? 50 ff 15 ?? ?? ?? ?? 39 5d f4 74 14 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*2) >=3
 
}