
rule Backdoor_Win32_Zegost_CK_bit{
	meta:
		description = "Backdoor:Win32/Zegost.CK!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_03_0 = {8a 14 1e 80 f2 ?? 88 14 1e 46 3b f7 7c ee } //1
		$a_03_1 = {6a 00 c6 44 ?? ?? 49 c6 44 ?? ?? 6e c6 44 ?? ?? 69 c6 44 ?? ?? 74 c6 44 ?? ?? 5f c6 44 ?? ?? 44 c6 44 ?? ?? 4c c6 44 ?? ?? 4c c6 44 ?? ?? 00 } //1
		$a_01_2 = {8b 44 24 08 8a 08 32 ca 02 ca 88 08 40 4e 75 f4 } //1
		$a_03_3 = {80 3c 1e 5c 75 35 56 8d 8d ?? ?? ?? ff 53 51 ff 15 ?? ?? ?? 00 8d 95 ?? ?? ?? ff 6a 00 52 ff 15 ?? ?? ?? 00 83 c4 14 83 f8 ff 75 0f 8d 85 ?? ?? ?? ff 6a 00 50 ff 15 ?? ?? ?? 00 8b fb 83 c9 ff 33 c0 46 f2 ae f7 d1 49 3b f1 72 b4 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1) >=3
 
}