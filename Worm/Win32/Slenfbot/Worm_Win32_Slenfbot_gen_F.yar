
rule Worm_Win32_Slenfbot_gen_F{
	meta:
		description = "Worm:Win32/Slenfbot.gen!F,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {69 6d 73 70 72 65 61 64 65 76 65 6e 74 00 [0-10] 68 00 74 00 74 00 70 00 [0-2f] 5c 49 43 51 2e 65 78 65 } //1
		$a_03_1 = {8b 45 f8 83 c0 01 89 45 f8 83 7d f8 ?? 7d ?? 8b 4d 08 03 4d f8 0f be 91 ?? ?? ?? ?? 33 55 fc 8b 45 f4 03 45 f8 88 10 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}