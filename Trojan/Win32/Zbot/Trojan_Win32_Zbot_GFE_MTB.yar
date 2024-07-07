
rule Trojan_Win32_Zbot_GFE_MTB{
	meta:
		description = "Trojan:Win32/Zbot.GFE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 5d 08 2b df 89 5d fc 80 3f 00 74 0f 8b 4d fc 47 0f b6 0c 39 0f b6 1f 2b cb 74 ec } //10
		$a_01_1 = {8b 47 04 6a 09 d1 e8 33 d2 59 f7 f1 85 d2 74 17 } //10
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10) >=20
 
}