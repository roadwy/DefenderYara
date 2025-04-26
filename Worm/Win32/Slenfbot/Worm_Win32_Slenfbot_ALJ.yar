
rule Worm_Win32_Slenfbot_ALJ{
	meta:
		description = "Worm:Win32/Slenfbot.ALJ,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 05 00 00 "
		
	strings :
		$a_03_0 = {8b 45 f8 83 c0 01 89 45 f8 83 7d f8 ?? 7d ?? 8b 4d 08 03 4d f8 0f be 91 95 38 20 03 33 55 fc 8b 45 f4 03 45 f8 88 10 8b 4d fc 83 c1 01 89 4d fc 8b 55 fc 81 e2 ff 00 00 80 79 ?? 4a 81 ca 00 ff ff ff } //5
		$a_01_1 = {6e 65 74 73 6b 25 64 25 64 2e 65 78 65 00 } //1
		$a_01_2 = {3a 5c 41 75 74 6f 72 75 6e 2e 69 6e 66 } //1 :\Autorun.inf
		$a_01_3 = {64 6f 77 6e 5f 65 78 65 63 00 00 00 21 } //1
		$a_01_4 = {23 23 34 75 63 6b 75 } //1 ##4ucku
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=8
 
}