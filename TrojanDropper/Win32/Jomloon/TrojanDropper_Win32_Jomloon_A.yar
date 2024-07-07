
rule TrojanDropper_Win32_Jomloon_A{
	meta:
		description = "TrojanDropper:Win32/Jomloon.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {6a 00 6a 02 6a 00 6a 00 68 ff 03 1f 00 90 01 01 8b ce 8b e8 e8 90 01 04 8b f8 83 ff ff 90 02 06 8b 90 01 01 24 90 01 01 8d 90 01 01 24 90 01 02 55 90 01 01 57 8b ce e8 90 01 04 6a 02 6a 00 6a 00 57 ff 15 90 01 02 40 00 90 00 } //1
		$a_01_1 = {8b 4d 0c 25 ff 00 00 00 89 4d 0c 89 45 08 50 51 8b 45 08 8b 4d 0c d2 c8 89 45 08 59 58 8a 45 08 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}