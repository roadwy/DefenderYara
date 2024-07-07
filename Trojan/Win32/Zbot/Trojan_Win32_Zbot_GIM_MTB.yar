
rule Trojan_Win32_Zbot_GIM_MTB{
	meta:
		description = "Trojan:Win32/Zbot.GIM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b 5d d8 c1 cb 13 0f b6 03 43 43 c1 cb 90 01 01 89 5d d8 b9 18 00 00 00 c1 c1 03 3b c1 72 23 2b c1 03 c0 8b 55 fc 81 c2 90 01 04 03 d0 03 d0 81 c2 90 01 04 89 55 fc 85 c0 75 c5 c3 90 00 } //10
		$a_80_1 = {63 6f 6e 77 75 72 2e 65 78 65 } //conwur.exe  1
	condition:
		((#a_02_0  & 1)*10+(#a_80_1  & 1)*1) >=11
 
}