
rule Backdoor_Win32_Isnup_B{
	meta:
		description = "Backdoor:Win32/Isnup.B,SIGNATURE_TYPE_PEHSTR_EXT,07 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {81 3f 75 70 64 61 75 16 b8 74 65 00 00 66 39 47 04 75 0b } //2
		$a_01_1 = {3c 3b 74 08 46 8a 04 3e 84 c0 75 f4 } //2
		$a_01_2 = {ff 45 fc 39 4d fc 7c e3 ff 45 f8 39 4d f8 7c d8 ff 45 f4 } //2
		$a_01_3 = {69 64 3d 25 73 26 70 6f 72 74 3d 25 64 26 69 73 6e 61 74 3d 25 64 26 75 70 74 69 6d 65 3d 25 64 26 76 65 72 3d 25 64 } //2 id=%s&port=%d&isnat=%d&uptime=%d&ver=%d
		$a_01_4 = {47 6f 6f 67 6c 65 20 62 6f 74 } //1 Google bot
		$a_01_5 = {4d 73 55 70 64 61 74 65 72 } //1 MsUpdater
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}