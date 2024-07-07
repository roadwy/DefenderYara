
rule Trojan_Win32_PikaBot_ZZ{
	meta:
		description = "Trojan:Win32/PikaBot.ZZ,SIGNATURE_TYPE_PEHSTR_EXT,ffffffc9 00 ffffffc9 00 03 00 00 "
		
	strings :
		$a_01_0 = {f1 d5 00 fa 4c 62 cc f4 0f 0b } //1
		$a_03_1 = {33 d2 8a 9c 90 01 05 6a 90 01 01 8b c6 59 f7 f1 0f b6 cb 0f b6 84 90 01 05 03 c7 03 c8 0f b6 f9 8a 84 90 01 05 88 84 90 01 05 46 88 9c 90 01 05 81 fe 00 01 00 00 72 90 00 } //100
		$a_03_2 = {8d 47 01 0f b6 f8 8a 8c 90 01 05 0f b6 d1 8d 04 1a 0f b6 d8 8a 84 90 01 05 88 84 90 01 05 88 8c 90 01 05 0f b6 84 90 01 05 03 c2 0f b6 c0 8a 84 90 01 05 32 44 90 01 02 88 84 90 01 05 46 83 fe 90 00 } //100
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*100+(#a_03_2  & 1)*100) >=201
 
}