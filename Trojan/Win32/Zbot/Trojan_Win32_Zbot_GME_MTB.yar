
rule Trojan_Win32_Zbot_GME_MTB{
	meta:
		description = "Trojan:Win32/Zbot.GME!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 03 00 00 "
		
	strings :
		$a_01_0 = {8b 45 08 89 45 fc 8b 4d 10 8b 55 10 83 ea 01 89 55 10 85 c9 74 1e 8b 45 08 8b 4d 0c 8a 11 88 10 8b 45 08 83 c0 01 89 45 08 8b 4d 0c 83 c1 01 89 4d 0c eb d2 8b 45 fc 8b e5 5d c2 0c 00 } //10
		$a_01_1 = {8b c8 c1 f9 05 8b 0c 8d 20 f2 43 00 83 e0 1f c1 e0 06 f6 44 08 04 01 74 cd 8b 04 08 5d c3 } //10
		$a_80_2 = {6e 4b 45 52 4e 45 4c 33 32 2e 44 4c 4c } //nKERNEL32.DLL  1
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_80_2  & 1)*1) >=21
 
}