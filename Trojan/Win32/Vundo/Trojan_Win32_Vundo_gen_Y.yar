
rule Trojan_Win32_Vundo_gen_Y{
	meta:
		description = "Trojan:Win32/Vundo.gen!Y,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 05 00 00 "
		
	strings :
		$a_03_0 = {6a 02 eb 01 53 53 ff 75 0c 56 ff 15 ?? ?? ?? ?? 53 8d 45 08 50 6a 0d 57 56 ff 15 } //1
		$a_01_1 = {c7 45 0c 92 ff ff ff eb 07 c7 45 0c 5b 00 00 00 50 ff 75 0c ff 75 08 e8 } //1
		$a_01_2 = {4e 8a 06 4e 8a 0e 32 c1 3c 22 88 4d 10 77 14 0f b6 d8 53 } //1
		$a_03_3 = {e9 93 00 00 00 56 57 6a 0a 59 be ?? ?? ?? ?? 8d 7d a8 f3 a5 6a 29 33 f6 } //1
		$a_03_4 = {74 5a 6a 02 53 68 54 ff ff ff 56 ff 15 ?? ?? ?? ?? 83 f8 ff 74 3f 57 6a 11 59 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1+(#a_03_4  & 1)*1) >=2
 
}