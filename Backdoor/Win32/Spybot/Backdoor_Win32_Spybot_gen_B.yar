
rule Backdoor_Win32_Spybot_gen_B{
	meta:
		description = "Backdoor:Win32/Spybot.gen!B,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {b9 1a 00 00 00 99 f7 f9 89 d7 83 c7 61 89 fa 88 14 35 90 01 04 46 8d 0d 90 01 04 83 c8 ff 40 80 3c 01 00 75 f9 90 00 } //1
		$a_01_1 = {86 00 74 70 67 75 78 62 73 66 7d 6e 8a 84 93 90 94 90 87 95 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}