
rule Backdoor_Win32_Poison_BL{
	meta:
		description = "Backdoor:Win32/Poison.BL,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {56 33 c9 8b c1 be 1f 00 00 00 99 f7 fe 8a 81 ?? ?? ?? ?? 32 c2 88 81 90 1b 00 41 81 f9 10 03 ?? ?? 7c df 8d 05 ?? ?? ?? ?? 50 8d 05 90 1b 00 ff d0 } //2
		$a_03_1 = {32 30 32 66 89 54 24 ?? 89 5c 24 ?? e8 } //1
		$a_03_2 = {6e 5c 52 75 c7 84 24 ?? 00 00 00 6e 00 00 00 ff 15 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}