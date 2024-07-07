
rule Virus_Win32_Mewsei_B{
	meta:
		description = "Virus:Win32/Mewsei.B,SIGNATURE_TYPE_PEHSTR,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {54 24 04 20 38 44 42 f7 83 f8 04 0f 96 c1 } //1
		$a_01_1 = {ac ff ff ff 89 04 24 e8 55 fd ff ff 89 f3 03 1c 06 c7 04 24 24 28 00 } //1
		$a_01_2 = {02 04 00 00 89 c6 85 ff 74 1f 8d 9d e4 fe ff ff 01 df } //1
		$a_01_3 = {ec 1c e8 a8 fe ff ff 84 c0 75 09 e8 86 ff ff ff 84 c0 74 0c } //1
		$a_01_4 = {b6 02 0f b6 19 38 d8 75 1a 84 c0 75 06 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}