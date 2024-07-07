
rule Trojan_Win32_Pikabot_DC_MTB{
	meta:
		description = "Trojan:Win32/Pikabot.DC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {0f b6 08 8b 45 e8 } //1
		$a_01_1 = {8b 45 f8 0f b6 44 10 10 } //1
		$a_01_2 = {33 c8 8b 45 dc } //1
		$a_01_3 = {03 45 e8 88 08 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}