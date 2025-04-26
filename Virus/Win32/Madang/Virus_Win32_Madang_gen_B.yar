
rule Virus_Win32_Madang_gen_B{
	meta:
		description = "Virus:Win32/Madang.gen!B,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {60 78 03 79 01 eb e8 } //1
		$a_03_1 = {66 81 3e 4d 5a [0-06] eb 75 ee 0f b7 7e 3c 03 fe 8b 6f 78 03 ee 8b 5d 20 } //1
		$a_01_2 = {41 6e 67 72 79 20 41 6e 67 65 6c 20 76 } //1 Angry Angel v
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}