
rule Backdoor_Win32_Drubot_gen_A{
	meta:
		description = "Backdoor:Win32/Drubot.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 04 00 00 "
		
	strings :
		$a_03_0 = {68 0f 27 00 00 68 e8 03 00 00 e8 90 01 02 ff ff 59 59 50 6a 09 6a 05 e8 90 00 } //1
		$a_01_1 = {8b 44 24 04 8a 10 84 d2 74 10 8b c8 32 54 24 08 88 11 8a 51 01 41 84 d2 75 f2 c3 } //1
		$a_03_2 = {7d 08 6a 02 58 e9 90 01 02 00 00 68 bd 01 00 00 66 c7 45 e8 02 00 e8 90 00 } //1
		$a_01_3 = {44 72 75 64 67 65 62 6f 74 00 } //1 牄摵敧潢t
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1) >=2
 
}