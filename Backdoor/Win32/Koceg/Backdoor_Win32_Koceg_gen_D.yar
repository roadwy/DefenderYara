
rule Backdoor_Win32_Koceg_gen_D{
	meta:
		description = "Backdoor:Win32/Koceg.gen!D,SIGNATURE_TYPE_PEHSTR_EXT,06 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {89 45 fc 83 7d fc ff 75 04 33 c0 eb 03 6a 01 58 } //1
		$a_01_1 = {39 45 fc 7d 16 8b 45 08 03 45 fc 0f be 00 33 45 0c 8b 4d 08 03 4d fc 88 01 eb d5 8b 45 08 } //2
		$a_01_2 = {b8 68 58 4d 56 bb 65 d4 85 86 b9 0a 00 00 00 66 ba 58 56 ed 89 5d e4 5b 83 4d fc ff eb 14 6a 01 58 c3 } //2
		$a_03_3 = {59 59 0f b6 45 fc 85 c0 75 0d 68 90 03 03 03 80 ee 36 80 4f 12 00 ff 15 90 01 02 40 00 eb 0b 68 10 27 00 00 ff 15 90 00 } //2
		$a_01_4 = {25 25 25 30 32 58 } //1 %%%02X
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_03_3  & 1)*2+(#a_01_4  & 1)*1) >=5
 
}