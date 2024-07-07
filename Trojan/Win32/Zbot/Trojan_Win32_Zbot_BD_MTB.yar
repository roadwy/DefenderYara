
rule Trojan_Win32_Zbot_BD_MTB{
	meta:
		description = "Trojan:Win32/Zbot.BD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {8a 06 0f b6 ca 83 e1 90 01 01 32 c2 d2 c8 88 06 fe c3 46 4f 75 c2 90 00 } //2
		$a_01_1 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //2 VirtualAlloc
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}