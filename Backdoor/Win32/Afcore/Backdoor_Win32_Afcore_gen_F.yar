
rule Backdoor_Win32_Afcore_gen_F{
	meta:
		description = "Backdoor:Win32/Afcore.gen!F,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_03_0 = {74 0c 6a 01 53 53 53 ff 55 f8 57 ff 56 70 8d 85 ?? ?? ?? ?? 50 ff 56 50 } //3
		$a_03_1 = {68 00 30 10 00 ff 90 17 03 01 04 04 36 76 ?? b6 ?? ?? ?? ?? 6a 00 ff 15 } //2
		$a_03_2 = {8a 4c 01 28 32 (0e|4e ?? 90 17) 02 05 05 8b 56 ?? 8b 96 ?? ?? ?? ?? 88 0c 10 } //1
		$a_03_3 = {8a 54 0a 28 8b 7e ?? 8d 86 ?? ?? ?? ?? 32 10 } //1
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*2+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=3
 
}