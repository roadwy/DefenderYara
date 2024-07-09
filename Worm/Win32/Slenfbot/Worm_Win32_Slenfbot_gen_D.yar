
rule Worm_Win32_Slenfbot_gen_D{
	meta:
		description = "Worm:Win32/Slenfbot.gen!D,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {53 6a 6f 68 ?? ?? ?? ?? ff 75 fc ff d6 83 f8 ff 0f 84 } //1
		$a_01_1 = {99 b9 e8 03 00 00 f7 f9 99 b9 3c 00 00 00 f7 f9 99 b9 3c 00 00 00 f7 f9 99 b9 18 00 00 00 f7 f9 99 b9 07 00 00 00 f7 f9 } //1
		$a_03_2 = {6a 04 68 00 10 00 00 68 6c 05 00 00 6a 00 8b ?? f4 ?? ff 15 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}