
rule Spammer_Win32_Hedsen_E{
	meta:
		description = "Spammer:Win32/Hedsen.E,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {53 56 b8 01 00 ff ff 8b 75 08 48 23 f0 81 f2 66 de 8a 31 f7 d0 40 40 8b c8 33 c0 41 66 8b 06 46 66 33 c2 74 05 } //2
		$a_01_1 = {0f b7 4e 3b 8b c6 48 89 45 fc 48 8d 44 01 19 b9 09 01 00 00 57 41 41 66 39 08 0f 85 85 00 00 00 8b 70 60 } //1
		$a_03_2 = {41 00 79 00 00 00 6a 70 ff 75 08 ff 15 90 01 02 41 00 a3 90 01 02 41 00 8b 45 fc 90 00 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=4
 
}