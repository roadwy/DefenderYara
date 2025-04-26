
rule Trojan_Win32_PikaBot_CCDG_MTB{
	meta:
		description = "Trojan:Win32/PikaBot.CCDG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {8b 45 e8 e9 } //1
		$a_01_1 = {03 45 f0 0f b6 08 } //1
		$a_01_2 = {8b 45 f0 33 d2 } //1
		$a_01_3 = {f7 f6 8b 45 fc } //1
		$a_01_4 = {0f b6 44 10 10 33 c8 } //1
		$a_01_5 = {8b 45 e8 03 45 f0 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}