
rule Trojan_Win32_Zbot_GHG_MTB{
	meta:
		description = "Trojan:Win32/Zbot.GHG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b ca 8b 49 3c c1 a4 25 ?? ?? ?? ?? 06 8b 4c 11 78 03 ca 8b 49 0c 31 05 78 45 40 00 8a 14 11 fe ca 80 f2 2f 19 94 25 ?? ?? ?? ?? 80 fa 65 0f 84 } //10
		$a_03_1 = {33 d7 33 d6 81 a4 25 ?? ?? ?? ?? 55 1c 00 00 51 19 94 25 } //10
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*10) >=20
 
}