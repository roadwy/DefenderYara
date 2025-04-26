
rule Trojan_Win32_Zbot_GLL_MTB{
	meta:
		description = "Trojan:Win32/Zbot.GLL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_02_0 = {2b fe 33 30 8b ff 8b 75 b8 81 c6 ?? ?? ?? ?? ba ?? ?? ?? ?? 81 f2 ?? ?? ?? ?? 23 f2 b9 ?? ?? ?? ?? c1 c9 05 b8 ?? ?? ?? ?? 35 ?? ?? ?? ?? e9 0b 01 00 00 } //10
		$a_01_1 = {33 07 33 c1 08 ff 8b ff 8b 16 8b 4d a0 81 f1 03 d4 f4 e4 03 f1 e9 f2 01 00 00 } //10
	condition:
		((#a_02_0  & 1)*10+(#a_01_1  & 1)*10) >=20
 
}