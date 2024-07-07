
rule Trojan_Win32_Trickbot_F_MTB{
	meta:
		description = "Trojan:Win32/Trickbot.F!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_02_0 = {55 8b ec eb 00 8b 45 08 0f af 45 08 2d 90 01 04 5d c3 90 00 } //1
		$a_02_1 = {55 8b ec 8b 45 08 0f af 45 08 2d 90 01 04 5d c3 90 00 } //1
		$a_00_2 = {0f b6 14 30 f7 da 8b 45 f8 0f b6 08 2b ca 8b 55 f8 88 0a 5e 8b e5 5d c3 } //2
		$a_02_3 = {89 45 fc 8b 0d 90 01 03 00 03 0d 90 01 03 00 0f b6 11 8b 45 fc 0f b6 08 03 ca 8b 55 fc 88 0a 8b e5 5d c3 90 00 } //2
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_00_2  & 1)*2+(#a_02_3  & 1)*2) >=3
 
}