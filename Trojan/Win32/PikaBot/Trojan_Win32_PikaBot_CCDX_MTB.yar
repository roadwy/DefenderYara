
rule Trojan_Win32_PikaBot_CCDX_MTB{
	meta:
		description = "Trojan:Win32/PikaBot.CCDX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {0f b6 08 8b 45 e4 33 d2 } //1
		$a_01_1 = {bb 05 00 00 00 83 c3 03 53 } //1
		$a_01_2 = {5e f7 f6 8b 45 f8 } //1
		$a_01_3 = {0f b6 44 10 10 33 c8 8b 45 dc } //1
		$a_01_4 = {03 45 e4 88 08 } //1
		$a_01_5 = {40 89 45 e4 8b 45 e4 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}