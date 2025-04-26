
rule Trojan_Win32_Zbot_PAZB_MTB{
	meta:
		description = "Trojan:Win32/Zbot.PAZB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_03_0 = {33 ca 8b 15 28 9f 41 00 03 95 ?? ?? ?? ?? 88 0a 8b 85 } //2
		$a_03_1 = {83 f1 44 8b 15 28 9f 41 00 03 95 ?? ?? ?? ?? 0f be 02 33 c1 8b 0d 28 9f 41 00 03 8d ?? ?? ?? ?? 88 01 8b 95 } //2
		$a_03_2 = {83 f2 73 a1 28 9f 41 00 03 85 ?? ?? ?? ?? 0f be 08 33 ca } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_03_2  & 1)*2) >=6
 
}