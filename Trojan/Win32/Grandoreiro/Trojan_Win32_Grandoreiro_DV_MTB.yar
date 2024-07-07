
rule Trojan_Win32_Grandoreiro_DV_MTB{
	meta:
		description = "Trojan:Win32/Grandoreiro.DV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {c5 fc 10 04 08 c5 fc 29 04 0a 83 c1 20 7c f1 5b c5 fc 11 0b c5 fc 11 12 c5 f8 77 5b c3 } //1
		$a_01_1 = {8b 45 f4 8b 55 e8 0f b7 7c 50 fe 33 fe 3b df } //1
		$a_01_2 = {8b de 8b 45 e4 40 40 89 45 e4 8b 45 fc } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}