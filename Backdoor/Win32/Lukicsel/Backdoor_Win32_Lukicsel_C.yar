
rule Backdoor_Win32_Lukicsel_C{
	meta:
		description = "Backdoor:Win32/Lukicsel.C,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {6a 00 6a 02 6a 02 e8 ?? ?? ?? ?? 8b d8 83 fb ff 74 ?? 66 c7 84 24 ?? ?? ?? ?? 02 00 6a 07 e8 ?? ?? ?? ?? 66 89 84 24 } //2
		$a_03_1 = {32 06 88 07 46 47 4b 75 ?? 5f 5e } //2
		$a_03_2 = {eb 07 6a 0a e8 ?? ?? ?? ?? 80 3b 00 74 f4 b2 01 a1 ?? ?? ?? ?? e8 ?? ?? ?? ?? 89 06 eb 07 } //2
		$a_01_3 = {8b 5d 08 8b c3 8b 10 ff 12 c6 43 0c 01 8b c3 8b 10 ff 52 04 b2 01 8b c3 8b 08 ff 51 fc 6a 00 } //1
		$a_03_4 = {e8 00 00 00 00 59 83 c1 ?? c1 (e0|e8) 03 01 c1 ff d1 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_03_2  & 1)*2+(#a_01_3  & 1)*1+(#a_03_4  & 1)*1) >=5
 
}