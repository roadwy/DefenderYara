
rule Trojan_Win32_Zbot_GPA_MTB{
	meta:
		description = "Trojan:Win32/Zbot.GPA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {32 d1 0f b6 d2 66 89 14 47 40 46 8a 16 84 d2 75 ef } //2
		$a_01_1 = {80 b4 05 00 ff ff ff 5c 40 3b c6 7c f3 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}