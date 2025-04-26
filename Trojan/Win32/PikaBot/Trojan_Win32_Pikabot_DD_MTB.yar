
rule Trojan_Win32_Pikabot_DD_MTB{
	meta:
		description = "Trojan:Win32/Pikabot.DD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {8b 45 ec 0f b6 4c 05 90 } //1
		$a_01_1 = {f7 f6 0f b6 44 15 8c } //1
		$a_01_2 = {33 c8 8b 45 ec } //1
		$a_01_3 = {88 4c 05 90 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}