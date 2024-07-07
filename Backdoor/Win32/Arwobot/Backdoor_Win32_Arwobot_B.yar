
rule Backdoor_Win32_Arwobot_B{
	meta:
		description = "Backdoor:Win32/Arwobot.B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {33 c0 8a 88 90 01 04 30 0c 37 40 83 f8 09 72 f1 83 3d 90 01 04 00 74 90 00 } //1
		$a_01_1 = {68 00 00 00 80 ff 75 0c c6 45 dc 52 c6 45 dd 61 c6 45 de 72 c6 45 df 21 c6 45 e0 1a c6 45 e1 07 88 5d e2 } //1
		$a_03_2 = {8d 45 fc 50 ff 15 90 01 04 83 f8 03 74 05 83 f8 04 75 14 8d 45 fc 50 ff 15 90 01 04 83 f8 01 75 05 e8 90 01 02 ff ff fe 4d fc 80 7d fc 62 75 cf 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}