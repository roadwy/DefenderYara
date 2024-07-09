
rule Trojan_Win32_Pikabot_DB_MTB{
	meta:
		description = "Trojan:Win32/Pikabot.DB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 05 00 00 "
		
	strings :
		$a_03_0 = {8b 5d cc 03 5d ac 81 eb ?? ?? ?? ?? 03 5d e8 } //10
		$a_01_1 = {8b 45 d8 31 18 } //10
		$a_01_2 = {ba 04 00 00 00 2b d0 01 55 d8 8b 45 e8 3b 45 d4 } //1
		$a_03_3 = {bb 04 00 00 00 2b d8 [0-0f] 2b d8 01 5d d8 8b 45 e8 3b 45 d4 } //1
		$a_01_4 = {83 45 e8 04 83 45 d8 04 8b 45 e8 3b 45 d4 } //1
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1+(#a_01_4  & 1)*1) >=21
 
}