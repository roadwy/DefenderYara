
rule TrojanDropper_Win32_Sirefef_gen_E{
	meta:
		description = "TrojanDropper:Win32/Sirefef.gen!E,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 "
		
	strings :
		$a_03_0 = {85 c0 75 05 b8 53 50 43 33 68 00 00 ?? ?? 50 ff 35 ?? ?? ?? ?? ff 55 ?? c9 c3 } //1
		$a_03_1 = {8d 4d fc 51 68 02 23 00 00 6a 00 50 ff 15 ?? ?? ?? ?? 85 c0 7c 10 68 ?? ?? ?? ?? 6a 00 ff 35 ?? ?? ?? ?? ff 55 fc } //1
		$a_03_2 = {8b 75 08 8b 4b 54 f3 a4 0f b7 53 06 0f b7 43 14 8d 44 18 18 85 d2 74 ?? 83 c0 14 } //10
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*10) >=11
 
}