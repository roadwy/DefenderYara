
rule Backdoor_Win32_Zegost_AK{
	meta:
		description = "Backdoor:Win32/Zegost.AK,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {23 25 64 3c 3c 3c 3c 3c 49 40 43 3c 3c 3c 3c 3c 25 73 21 } //1 #%d<<<<<I@C<<<<<%s!
		$a_03_1 = {68 00 e9 a4 35 57 66 89 45 ?? e8 } //1
		$a_03_2 = {ff ff 77 c6 85 ?? ?? ff ff 77 88 9d [0-10] c6 84 1d ?? ?? ?? ?? 03 c6 84 1d ?? ?? ?? ?? 63 c6 84 1d ?? ?? ?? ?? 6f c6 84 1d ?? ?? ?? ?? 6d 80 a4 1d ?? ?? ?? ?? 00 } //1
		$a_02_3 = {ff 45 08 81 7d 08 64 19 00 00 0f 8c ?? ?? ff ff } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_02_3  & 1)*1) >=3
 
}